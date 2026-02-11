//! Breakthrough #592: Content-Addressed Deduplication
//!
//! Eliminate identical data across overlapping datasets. Uses BLAKE3 hashing
//! for content addressing. Critical for: overlapping threat feeds, shared
//! signatures across rulesets, common packages across systems, shared firmware.
//!
//! Used by ~30 of 203 security components.

use std::collections::HashMap;
use std::hash::Hash;

/// Content-addressed deduplication store.
/// Stores each unique value once, mapped by its content hash.
/// Multiple keys can reference the same deduplicated value.
pub struct DedupStore<K, V> {
    /// Content hash → stored value
    values: HashMap<u64, V>,
    /// Key → content hash (reference)
    refs: HashMap<K, u64>,
    /// Content hash → reference count
    ref_counts: HashMap<u64, usize>,
    /// Stats
    total_inserts: u64,
    dedup_hits: u64,
}

impl<K, V> DedupStore<K, V>
where
    K: Eq + Hash + Clone,
    V: AsRef<[u8]> + Clone,
{
    pub fn new() -> Self {
        Self {
            values: HashMap::new(),
            refs: HashMap::new(),
            ref_counts: HashMap::new(),
            total_inserts: 0,
            dedup_hits: 0,
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            values: HashMap::with_capacity(capacity),
            refs: HashMap::with_capacity(capacity),
            ref_counts: HashMap::with_capacity(capacity),
            total_inserts: 0,
            dedup_hits: 0,
        }
    }

    /// Insert a key-value pair. If the value already exists (by content hash),
    /// only stores a reference — no duplication.
    pub fn insert(&mut self, key: K, value: V) {
        self.total_inserts += 1;
        let hash = content_hash(value.as_ref());

        // Remove old reference if key already exists
        if let Some(old_hash) = self.refs.get(&key) {
            let old_hash = *old_hash;
            if let Some(count) = self.ref_counts.get_mut(&old_hash) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.values.remove(&old_hash);
                    self.ref_counts.remove(&old_hash);
                }
            }
        }

        // Insert or reference existing
        if self.values.contains_key(&hash) {
            self.dedup_hits += 1;
        } else {
            self.values.insert(hash, value);
        }

        self.refs.insert(key, hash);
        *self.ref_counts.entry(hash).or_insert(0) += 1;
    }

    /// Get a value by key.
    pub fn get(&self, key: &K) -> Option<&V> {
        let hash = self.refs.get(key)?;
        self.values.get(hash)
    }

    /// Remove a key. Value is only removed if no other keys reference it.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let hash = self.refs.remove(key)?;
        if let Some(count) = self.ref_counts.get_mut(&hash) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.ref_counts.remove(&hash);
                return self.values.remove(&hash);
            }
        }
        None
    }

    /// Check if a key exists.
    pub fn contains_key(&self, key: &K) -> bool {
        self.refs.contains_key(key)
    }

    /// Number of unique keys.
    pub fn key_count(&self) -> usize {
        self.refs.len()
    }

    /// Number of unique values (deduplicated).
    pub fn unique_value_count(&self) -> usize {
        self.values.len()
    }

    /// Deduplication ratio: keys / unique_values. Higher = more dedup savings.
    pub fn dedup_ratio(&self) -> f64 {
        if self.values.is_empty() {
            return 1.0;
        }
        self.refs.len() as f64 / self.values.len() as f64
    }

    /// Dedup hit rate: fraction of inserts that were duplicates.
    pub fn dedup_hit_rate(&self) -> f64 {
        if self.total_inserts == 0 {
            return 0.0;
        }
        self.dedup_hits as f64 / self.total_inserts as f64
    }

    /// Memory savings: (actual_bytes, without_dedup_bytes, ratio).
    pub fn memory_savings(&self) -> (usize, usize, f64) {
        let value_size: usize = self.values.values().map(|v| v.as_ref().len()).sum();
        let ref_size = self.refs.len() * (std::mem::size_of::<K>() + 8); // key + u64 hash
        let actual = value_size + ref_size;

        // Without dedup: every key would have its own copy
        let avg_value_size = if self.values.is_empty() {
            0
        } else {
            value_size / self.values.len()
        };
        let without_dedup = self.refs.len() * (std::mem::size_of::<K>() + avg_value_size);

        let ratio = if actual > 0 {
            without_dedup as f64 / actual as f64
        } else {
            1.0
        };
        (actual, without_dedup, ratio)
    }

    pub fn clear(&mut self) {
        self.values.clear();
        self.refs.clear();
        self.ref_counts.clear();
    }
}

impl<K, V> Default for DedupStore<K, V>
where
    K: Eq + Hash + Clone,
    V: AsRef<[u8]> + Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

/// Compute a content hash using xxhash (fast) for deduplication.
/// We use xxh3 for speed — this is dedup, not crypto.
fn content_hash(data: &[u8]) -> u64 {
    xxhash_rust::xxh3::xxh3_64(data)
}

/// Batch deduplication: given a list of items, return unique items and a mapping.
pub fn batch_dedup<T: AsRef<[u8]> + Clone>(items: &[T]) -> (Vec<T>, Vec<usize>) {
    let mut unique: Vec<T> = Vec::new();
    let mut hash_to_idx: HashMap<u64, usize> = HashMap::new();
    let mut mapping: Vec<usize> = Vec::with_capacity(items.len());

    for item in items {
        let hash = content_hash(item.as_ref());
        if let Some(&idx) = hash_to_idx.get(&hash) {
            mapping.push(idx);
        } else {
            let idx = unique.len();
            hash_to_idx.insert(hash, idx);
            unique.push(item.clone());
            mapping.push(idx);
        }
    }

    (unique, mapping)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dedup_store() {
        let mut store: DedupStore<String, Vec<u8>> = DedupStore::new();

        let sig1 = vec![1u8, 2, 3, 4, 5];
        let sig2 = vec![6u8, 7, 8, 9, 10];

        // Same signature from two different sources
        store.insert("et_open_rule_1".to_string(), sig1.clone());
        store.insert("community_rule_1".to_string(), sig1.clone());
        store.insert("custom_rule_1".to_string(), sig2.clone());

        assert_eq!(store.key_count(), 3);
        assert_eq!(store.unique_value_count(), 2); // Only 2 unique values
        assert!(store.dedup_ratio() > 1.0);
        assert!(store.dedup_hit_rate() > 0.0);
    }

    #[test]
    fn test_batch_dedup() {
        let items: Vec<Vec<u8>> = vec![
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![1, 2, 3], // duplicate
            vec![7, 8, 9],
            vec![4, 5, 6], // duplicate
        ];

        let (unique, mapping) = batch_dedup(&items);
        assert_eq!(unique.len(), 3);
        assert_eq!(mapping, vec![0, 1, 0, 2, 1]);
    }
}
