//! Breakthrough #569: Entry Pruning
//!
//! Time-based and priority-based eviction of entries from bounded collections.
//! Keeps memory bounded by removing the least important entries when capacity
//! is reached. Uses φ-weighted scoring: score = priority / age^φ.
//!
//! Used by ~20 of 203 security components (rate limiters, scan trackers,
//! session tables, alert feeds, cache expiry, etc.)

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

/// An entry with priority and timestamp metadata for pruning decisions.
struct PruneEntry<V> {
    value: V,
    priority: f64,
    inserted: Instant,
    last_access: Instant,
    ttl: Option<Duration>,
}

/// A bounded map that automatically prunes entries when at capacity.
/// Uses φ-weighted scoring for eviction: entries with low priority
/// and old age are pruned first.
pub struct PruningMap<K, V> {
    entries: HashMap<K, PruneEntry<V>>,
    max_entries: usize,
    default_ttl: Option<Duration>,
    total_pruned: u64,
}

impl<K, V> PruningMap<K, V>
where
    K: Eq + Hash + Clone,
{
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(max_entries),
            max_entries,
            default_ttl: None,
            total_pruned: 0,
        }
    }

    /// Set a default TTL for all entries.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.default_ttl = Some(ttl);
        self
    }

    /// Insert with default priority (1.0).
    pub fn insert(&mut self, key: K, value: V) {
        self.insert_with_priority(key, value, 1.0);
    }

    /// Insert with explicit priority. Higher priority = harder to prune.
    pub fn insert_with_priority(&mut self, key: K, value: V, priority: f64) {
        // Prune expired entries first
        self.prune_expired();

        // If still at capacity, prune lowest-scored entries
        while self.entries.len() >= self.max_entries {
            self.prune_lowest();
        }

        let now = Instant::now();
        self.entries.insert(
            key,
            PruneEntry {
                value,
                priority,
                inserted: now,
                last_access: now,
                ttl: self.default_ttl,
            },
        );
    }

    /// Get a value, updating its last access time.
    pub fn get(&mut self, key: &K) -> Option<&V> {
        // Check TTL expiry first
        let expired = self.entries.get(key).and_then(|entry| {
            entry.ttl.and_then(|ttl| {
                if entry.inserted.elapsed() > ttl {
                    Some(())
                } else {
                    None
                }
            })
        });
        if expired.is_some() {
            self.entries.remove(key);
            self.total_pruned += 1;
            return None;
        }

        if let Some(entry) = self.entries.get_mut(key) {
            entry.last_access = Instant::now();
            Some(&entry.value)
        } else {
            None
        }
    }

    /// Get a value without updating access time.
    pub fn peek(&self, key: &K) -> Option<&V> {
        self.entries.get(key).map(|e| &e.value)
    }

    /// Get a mutable reference to a value.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        let expired = self.entries.get(key).and_then(|entry| {
            entry.ttl.and_then(|ttl| {
                if entry.inserted.elapsed() > ttl {
                    Some(())
                } else {
                    None
                }
            })
        });
        if expired.is_some() {
            self.entries.remove(key);
            self.total_pruned += 1;
            return None;
        }

        if let Some(entry) = self.entries.get_mut(key) {
            entry.last_access = Instant::now();
            Some(&mut entry.value)
        } else {
            None
        }
    }

    /// Remove an entry.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.entries.remove(key).map(|e| e.value)
    }

    /// Prune all expired entries (past TTL).
    pub fn prune_expired(&mut self) {
        let now = Instant::now();
        let before = self.entries.len();
        self.entries.retain(|_, entry| {
            if let Some(ttl) = entry.ttl {
                now.duration_since(entry.inserted) <= ttl
            } else {
                true
            }
        });
        self.total_pruned += (before - self.entries.len()) as u64;
    }

    /// Prune the single lowest-scored entry.
    /// Score = priority / age^φ (higher score = keep, lower score = prune).
    fn prune_lowest(&mut self) {
        let now = Instant::now();
        let mut worst_key: Option<K> = None;
        let mut worst_score = f64::MAX;

        for (k, entry) in &self.entries {
            let age = now.duration_since(entry.last_access).as_secs_f64().max(0.001);
            let score = entry.priority / age.powf(crate::PHI);
            if score < worst_score {
                worst_score = score;
                worst_key = Some(k.clone());
            }
        }

        if let Some(key) = worst_key {
            self.entries.remove(&key);
            self.total_pruned += 1;
        }
    }

    /// Prune entries older than a given duration.
    pub fn prune_older_than(&mut self, max_age: Duration) {
        let now = Instant::now();
        let before = self.entries.len();
        self.entries.retain(|_, entry| {
            now.duration_since(entry.last_access) <= max_age
        });
        self.total_pruned += (before - self.entries.len()) as u64;
    }

    /// Prune entries below a priority threshold.
    pub fn prune_below_priority(&mut self, min_priority: f64) {
        let before = self.entries.len();
        self.entries.retain(|_, entry| entry.priority >= min_priority);
        self.total_pruned += (before - self.entries.len()) as u64;
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.max_entries
    }

    pub fn total_pruned(&self) -> u64 {
        self.total_pruned
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.entries.contains_key(key)
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Iterate over all current entries.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.entries.iter().map(|(k, e)| (k, &e.value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pruning_map_capacity() {
        let mut map: PruningMap<u32, String> = PruningMap::new(5);

        for i in 0..10 {
            map.insert(i, format!("val_{}", i));
        }

        // Should never exceed capacity
        assert!(map.len() <= 5);
        assert!(map.total_pruned() >= 5);
    }

    #[test]
    fn test_pruning_map_priority() {
        let mut map: PruningMap<&str, i32> = PruningMap::new(3);

        map.insert_with_priority("low", 1, 0.1);
        map.insert_with_priority("med", 2, 1.0);
        map.insert_with_priority("high", 3, 10.0);

        // Force pruning by inserting a 4th
        map.insert_with_priority("new", 4, 5.0);

        // Low priority should be pruned first
        assert!(map.len() <= 3);
        assert!(!map.contains_key(&"low"));
        assert!(map.contains_key(&"high"));
    }

    #[test]
    fn test_pruning_ttl() {
        let mut map: PruningMap<u32, u32> =
            PruningMap::new(100).with_ttl(Duration::from_millis(10));

        map.insert(1, 100);
        std::thread::sleep(Duration::from_millis(20));

        // Should be expired
        assert!(map.get(&1).is_none());
    }
}
