//! Breakthrough #2: Tiered Cache
//!
//! Generic hot/warm/cold cache with automatic promotion/demotion.
//! - **Hot tier**: Uncompressed, fastest access, bounded by φ⁻² fraction of capacity
//! - **Warm tier**: Uncompressed, medium access, bounded by remaining φ⁻¹ fraction
//! - **Cold tier**: LZ4-compressed, slowest access, stores everything else
//!
//! Used by ~85 of 203 security components (anything with lookup tables or state).

use std::collections::HashMap;
use std::hash::Hash;
use std::time::Instant;
use parking_lot::RwLock;
use serde::{Serialize, de::DeserializeOwned};
use crate::compression;
use crate::metrics::MemoryMetrics;

/// A single entry in the cache, tracking access metadata.
struct CacheEntry<V> {
    value: CachedValue<V>,
    access_count: u32,
    last_access: Instant,
    size_bytes: usize,
}

enum CachedValue<V> {
    /// Hot/warm: stored directly
    Direct(V),
    /// Cold: LZ4-compressed bytes
    Compressed(Vec<u8>),
}

/// Three-tier cache with automatic promotion/demotion and optional compression.
pub struct TieredCache<K, V> {
    hot: RwLock<HashMap<K, CacheEntry<V>>>,
    warm: RwLock<HashMap<K, CacheEntry<V>>>,
    cold: RwLock<HashMap<K, CacheEntry<V>>>,
    hot_capacity: usize,
    warm_capacity: usize,
    cold_capacity: usize,
    promote_threshold: u32,
    demote_after: std::time::Duration,
    compress_cold: bool,
    metrics: Option<MemoryMetrics>,
    component_name: String,
    total_bytes: std::sync::atomic::AtomicUsize,
}

impl<K, V> TieredCache<K, V>
where
    K: Eq + Hash + Clone + Send + Sync,
    V: Clone + Serialize + DeserializeOwned + Send + Sync,
{
    /// Create a new tiered cache with the given total capacity (number of entries).
    pub fn new(total_capacity: usize) -> Self {
        let inv_phi_sq = crate::INV_PHI * crate::INV_PHI;
        let hot_cap = (total_capacity as f64 * inv_phi_sq) as usize;
        let warm_cap = (total_capacity as f64 * (crate::INV_PHI - inv_phi_sq)) as usize;
        let cold_cap = total_capacity - hot_cap - warm_cap;

        Self {
            hot: RwLock::new(HashMap::with_capacity(hot_cap)),
            warm: RwLock::new(HashMap::with_capacity(warm_cap)),
            cold: RwLock::new(HashMap::with_capacity(cold_cap)),
            hot_capacity: hot_cap.max(1),
            warm_capacity: warm_cap.max(1),
            cold_capacity: cold_cap.max(1),
            promote_threshold: 3,
            demote_after: std::time::Duration::from_secs(300),
            compress_cold: true,
            metrics: None,
            component_name: String::new(),
            total_bytes: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Attach memory metrics tracking (Breakthrough #6 integration).
    pub fn with_metrics(mut self, metrics: MemoryMetrics, component_name: &str) -> Self {
        self.metrics = Some(metrics);
        self.component_name = component_name.to_string();
        self
    }

    /// Set the access count threshold for promotion from cold → warm or warm → hot.
    pub fn with_promote_threshold(mut self, threshold: u32) -> Self {
        self.promote_threshold = threshold;
        self
    }

    /// Set the idle duration before demotion from hot → warm or warm → cold.
    pub fn with_demote_after(mut self, duration: std::time::Duration) -> Self {
        self.demote_after = duration;
        self
    }

    /// Disable cold tier compression.
    pub fn without_compression(mut self) -> Self {
        self.compress_cold = false;
        self
    }

    /// Get a value from the cache. Automatically promotes entries on access.
    pub fn get(&self, key: &K) -> Option<V> {
        // Check hot tier first
        {
            let mut hot = self.hot.write();
            if let Some(entry) = hot.get_mut(key) {
                entry.access_count += 1;
                entry.last_access = Instant::now();
                if let CachedValue::Direct(ref v) = entry.value {
                    return Some(v.clone());
                }
            }
        }

        // Check warm tier
        {
            let mut warm = self.warm.write();
            if let Some(entry) = warm.get_mut(key) {
                entry.access_count += 1;
                entry.last_access = Instant::now();
                let value = if let CachedValue::Direct(ref v) = entry.value {
                    Some(v.clone())
                } else {
                    None
                };

                // Promote to hot if threshold met
                if entry.access_count >= self.promote_threshold {
                    if let Some(removed) = warm.remove(key) {
                        if let CachedValue::Direct(v) = removed.value {
                            self.insert_to_hot(key.clone(), v.clone(), removed.size_bytes);
                            return Some(v);
                        }
                    }
                }

                return value;
            }
        }

        // Check cold tier
        {
            let mut cold = self.cold.write();
            if let Some(entry) = cold.get_mut(key) {
                entry.access_count += 1;
                entry.last_access = Instant::now();

                let value = match &entry.value {
                    CachedValue::Direct(v) => Some(v.clone()),
                    CachedValue::Compressed(bytes) => {
                        compression::decompress_and_deserialize::<V>(bytes).ok()
                    }
                };

                // Promote to warm if threshold met
                if entry.access_count >= self.promote_threshold {
                    if let Some(removed) = cold.remove(key) {
                        if let Some(ref v) = value {
                            self.insert_to_warm(key.clone(), v.clone(), removed.size_bytes);
                        }
                    }
                }

                return value;
            }
        }

        None
    }

    /// Insert a value into the cache. New entries go to hot tier.
    pub fn insert(&self, key: K, value: V) {
        let size = std::mem::size_of::<V>();
        self.insert_to_hot(key, value, size);
    }

    /// Insert a value with a known size in bytes.
    pub fn insert_with_size(&self, key: K, value: V, size_bytes: usize) {
        self.insert_to_hot(key, value, size_bytes);
    }

    fn insert_to_hot(&self, key: K, value: V, size_bytes: usize) {
        let mut hot = self.hot.write();

        // Evict from hot to warm if at capacity
        if hot.len() >= self.hot_capacity {
            self.demote_oldest_from_hot(&mut hot);
        }

        hot.insert(
            key,
            CacheEntry {
                value: CachedValue::Direct(value),
                access_count: 1,
                last_access: Instant::now(),
                size_bytes,
            },
        );

        self.track_add(size_bytes);
    }

    fn insert_to_warm(&self, key: K, value: V, size_bytes: usize) {
        let mut warm = self.warm.write();

        if warm.len() >= self.warm_capacity {
            self.demote_oldest_from_warm(&mut warm);
        }

        warm.insert(
            key,
            CacheEntry {
                value: CachedValue::Direct(value),
                access_count: 1,
                last_access: Instant::now(),
                size_bytes,
            },
        );
    }

    fn demote_oldest_from_hot(&self, hot: &mut HashMap<K, CacheEntry<V>>) {
        // Find the entry with the oldest last_access
        let oldest_key = hot
            .iter()
            .min_by_key(|(_, e)| e.last_access)
            .map(|(k, _)| k.clone());

        if let Some(key) = oldest_key {
            if let Some(entry) = hot.remove(&key) {
                if let CachedValue::Direct(v) = entry.value {
                    self.insert_to_warm(key, v, entry.size_bytes);
                }
            }
        }
    }

    fn demote_oldest_from_warm(&self, warm: &mut HashMap<K, CacheEntry<V>>) {
        let oldest_key = warm
            .iter()
            .min_by_key(|(_, e)| e.last_access)
            .map(|(k, _)| k.clone());

        if let Some(key) = oldest_key {
            if let Some(entry) = warm.remove(&key) {
                if let CachedValue::Direct(v) = entry.value {
                    self.insert_to_cold(key, v, entry.size_bytes);
                }
            }
        }
    }

    fn insert_to_cold(&self, key: K, value: V, size_bytes: usize) {
        let mut cold = self.cold.write();

        // Evict from cold if at capacity (true eviction — data is gone)
        if cold.len() >= self.cold_capacity {
            let oldest_key = cold
                .iter()
                .min_by_key(|(_, e)| e.last_access)
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest_key {
                if let Some(removed) = cold.remove(&k) {
                    self.track_remove(removed.size_bytes);
                }
            }
        }

        let cached_value = if self.compress_cold {
            match compression::serialize_and_compress(&value) {
                Ok(bytes) => {
                    let compressed_size = bytes.len();
                    // Track memory savings from compression
                    if compressed_size < size_bytes {
                        self.track_remove(size_bytes - compressed_size);
                    }
                    CachedValue::Compressed(bytes)
                }
                Err(_) => CachedValue::Direct(value),
            }
        } else {
            CachedValue::Direct(value)
        };

        cold.insert(
            key,
            CacheEntry {
                value: cached_value,
                access_count: 0,
                last_access: Instant::now(),
                size_bytes,
            },
        );
    }

    /// Run a demotion pass — move idle entries down tiers.
    pub fn demote_idle(&self) {
        let now = Instant::now();

        // Demote from hot → warm
        let mut to_demote_from_hot = Vec::new();
        {
            let hot = self.hot.read();
            for (k, e) in hot.iter() {
                if now.duration_since(e.last_access) > self.demote_after {
                    to_demote_from_hot.push(k.clone());
                }
            }
        }
        {
            let mut hot = self.hot.write();
            for key in to_demote_from_hot {
                if let Some(entry) = hot.remove(&key) {
                    if let CachedValue::Direct(v) = entry.value {
                        self.insert_to_warm(key, v, entry.size_bytes);
                    }
                }
            }
        }

        // Demote from warm → cold
        let mut to_demote_from_warm = Vec::new();
        {
            let warm = self.warm.read();
            for (k, e) in warm.iter() {
                if now.duration_since(e.last_access) > self.demote_after * 2 {
                    to_demote_from_warm.push(k.clone());
                }
            }
        }
        {
            let mut warm = self.warm.write();
            for key in to_demote_from_warm {
                if let Some(entry) = warm.remove(&key) {
                    if let CachedValue::Direct(v) = entry.value {
                        self.insert_to_cold(key, v, entry.size_bytes);
                    }
                }
            }
        }
    }

    /// Remove an entry from any tier.
    pub fn remove(&self, key: &K) -> Option<V> {
        if let Some(entry) = self.hot.write().remove(key) {
            self.track_remove(entry.size_bytes);
            if let CachedValue::Direct(v) = entry.value {
                return Some(v);
            }
        }
        if let Some(entry) = self.warm.write().remove(key) {
            self.track_remove(entry.size_bytes);
            if let CachedValue::Direct(v) = entry.value {
                return Some(v);
            }
        }
        if let Some(entry) = self.cold.write().remove(key) {
            self.track_remove(entry.size_bytes);
            match entry.value {
                CachedValue::Direct(v) => return Some(v),
                CachedValue::Compressed(bytes) => {
                    return compression::decompress_and_deserialize::<V>(&bytes).ok();
                }
            }
        }
        None
    }

    /// Total number of entries across all tiers.
    pub fn len(&self) -> usize {
        self.hot.read().len() + self.warm.read().len() + self.cold.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of entries per tier.
    pub fn tier_sizes(&self) -> (usize, usize, usize) {
        (
            self.hot.read().len(),
            self.warm.read().len(),
            self.cold.read().len(),
        )
    }

    /// Approximate memory usage in bytes.
    pub fn memory_usage(&self) -> usize {
        self.total_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Clear all tiers.
    pub fn clear(&self) {
        self.hot.write().clear();
        self.warm.write().clear();
        self.cold.write().clear();
        let old = self
            .total_bytes
            .swap(0, std::sync::atomic::Ordering::Relaxed);
        if let Some(ref m) = self.metrics {
            m.record_deallocation(&self.component_name, old);
        }
    }

    fn track_add(&self, bytes: usize) {
        self.total_bytes
            .fetch_add(bytes, std::sync::atomic::Ordering::Relaxed);
        if let Some(ref m) = self.metrics {
            let _ = m.record_allocation(&self.component_name, bytes);
        }
    }

    fn track_remove(&self, bytes: usize) {
        self.total_bytes
            .fetch_sub(bytes, std::sync::atomic::Ordering::Relaxed);
        if let Some(ref m) = self.metrics {
            m.record_deallocation(&self.component_name, bytes);
        }
    }
}
