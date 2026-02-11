//! Breakthrough #461: Differential Storage
//!
//! Store only changes from a baseline snapshot. When data evolves slowly
//! (configs, baselines, firmware versions, ARP tables, etc.), this reduces
//! storage by 10-50× compared to storing full snapshots.
//!
//! Used by ~130 of 203 security components.

use crate::compression;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::Hash;

/// A diff operation on a key-value store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiffOp<K, V> {
    Insert(K, V),
    Update(K, V),
    Delete(K),
}

/// A single diff — a set of changes from the previous state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diff<K, V> {
    pub ops: Vec<DiffOp<K, V>>,
    pub timestamp: i64,
    pub compressed_size: Option<usize>,
}

/// Differential storage engine for key-value data.
/// Maintains a baseline snapshot plus a chain of diffs.
/// Periodically compacts (re-snapshots) when the diff chain gets too long.
pub struct DifferentialStore<K, V> {
    baseline: HashMap<K, V>,
    diffs: Vec<Diff<K, V>>,
    max_diff_chain: usize,
    compress_diffs: bool,
    /// Compressed archived diffs (after compaction)
    archived_diffs: Vec<Vec<u8>>,
}

impl<K, V> DifferentialStore<K, V>
where
    K: Eq + Hash + Clone + Serialize + for<'de> Deserialize<'de> + Send + Sync,
    V: Clone + PartialEq + Serialize + for<'de> Deserialize<'de> + Send + Sync,
{
    pub fn new() -> Self {
        Self {
            baseline: HashMap::new(),
            diffs: Vec::new(),
            max_diff_chain: 64,
            compress_diffs: true,
            archived_diffs: Vec::new(),
        }
    }

    pub fn with_max_chain(mut self, max: usize) -> Self {
        self.max_diff_chain = max;
        self
    }

    pub fn with_compression(mut self, compress: bool) -> Self {
        self.compress_diffs = compress;
        self
    }

    /// Set the baseline snapshot from a full state.
    pub fn set_baseline(&mut self, state: HashMap<K, V>) {
        self.baseline = state;
        self.diffs.clear();
    }

    /// Compute a diff between the current materialized state and a new state,
    /// then store only the diff.
    pub fn apply_new_state(&mut self, new_state: &HashMap<K, V>) {
        let current = self.materialize();
        let mut ops = Vec::new();

        // Find inserts and updates
        for (k, v) in new_state {
            match current.get(k) {
                None => ops.push(DiffOp::Insert(k.clone(), v.clone())),
                Some(old_v) if old_v != v => ops.push(DiffOp::Update(k.clone(), v.clone())),
                _ => {}
            }
        }

        // Find deletes
        for k in current.keys() {
            if !new_state.contains_key(k) {
                ops.push(DiffOp::Delete(k.clone()));
            }
        }

        if !ops.is_empty() {
            let diff = Diff {
                ops,
                timestamp: chrono::Utc::now().timestamp(),
                compressed_size: None,
            };
            self.diffs.push(diff);
        }

        // Compact if chain is too long
        if self.diffs.len() >= self.max_diff_chain {
            self.compact();
        }
    }

    /// Record a single change without computing a full diff.
    pub fn record_insert(&mut self, key: K, value: V) {
        self.push_op(DiffOp::Insert(key, value));
    }

    pub fn record_update(&mut self, key: K, value: V) {
        self.push_op(DiffOp::Update(key, value));
    }

    pub fn record_delete(&mut self, key: K) {
        self.push_op(DiffOp::Delete(key));
    }

    fn push_op(&mut self, op: DiffOp<K, V>) {
        let diff = Diff {
            ops: vec![op],
            timestamp: chrono::Utc::now().timestamp(),
            compressed_size: None,
        };
        self.diffs.push(diff);

        if self.diffs.len() >= self.max_diff_chain {
            self.compact();
        }
    }

    /// Materialize the current state by replaying diffs on top of baseline.
    pub fn materialize(&self) -> HashMap<K, V> {
        let mut state = self.baseline.clone();
        for diff in &self.diffs {
            for op in &diff.ops {
                match op {
                    DiffOp::Insert(k, v) | DiffOp::Update(k, v) => {
                        state.insert(k.clone(), v.clone());
                    }
                    DiffOp::Delete(k) => {
                        state.remove(k);
                    }
                }
            }
        }
        state
    }

    /// Get a single value from the materialized state.
    pub fn get(&self, key: &K) -> Option<V> {
        // Walk diffs in reverse to find latest operation on this key
        for diff in self.diffs.iter().rev() {
            for op in diff.ops.iter().rev() {
                match op {
                    DiffOp::Insert(k, v) | DiffOp::Update(k, v) if k == key => {
                        return Some(v.clone());
                    }
                    DiffOp::Delete(k) if k == key => {
                        return None;
                    }
                    _ => {}
                }
            }
        }
        self.baseline.get(key).cloned()
    }

    /// Compact: materialize current state as new baseline, clear diffs.
    pub fn compact(&mut self) {
        // Archive old diffs if compression is enabled
        if self.compress_diffs && !self.diffs.is_empty() {
            if let Ok(compressed) = compression::serialize_and_compress(&self.diffs) {
                self.archived_diffs.push(compressed);
            }
        }

        self.baseline = self.materialize();
        self.diffs.clear();
    }

    /// Number of pending diffs (before compaction).
    pub fn diff_count(&self) -> usize {
        self.diffs.len()
    }

    /// Total number of operations across all pending diffs.
    pub fn total_ops(&self) -> usize {
        self.diffs.iter().map(|d| d.ops.len()).sum()
    }

    /// Number of entries in the baseline.
    pub fn baseline_size(&self) -> usize {
        self.baseline.len()
    }

    /// Number of archived (compacted + compressed) diff batches.
    pub fn archived_count(&self) -> usize {
        self.archived_diffs.len()
    }

    /// Approximate memory savings vs storing full snapshots.
    /// Returns (current_approx_bytes, full_snapshot_bytes, savings_ratio).
    pub fn memory_savings(&self) -> (usize, usize, f64) {
        let baseline_size = self.baseline.len() * (std::mem::size_of::<K>() + std::mem::size_of::<V>());
        let diff_size = self.total_ops() * (std::mem::size_of::<K>() + std::mem::size_of::<V>());
        let current = baseline_size + diff_size;

        // Full snapshot would be baseline_size per snapshot × (1 + diff_count)
        let full = baseline_size * (1 + self.diffs.len());

        let ratio = if current > 0 {
            full as f64 / current as f64
        } else {
            1.0
        };

        (current, full, ratio)
    }
}

impl<K, V> Default for DifferentialStore<K, V>
where
    K: Eq + Hash + Clone + Serialize + for<'de> Deserialize<'de> + Send + Sync,
    V: Clone + PartialEq + Serialize + for<'de> Deserialize<'de> + Send + Sync,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_differential_basic() {
        let mut store: DifferentialStore<String, String> = DifferentialStore::new();

        let mut state1 = HashMap::new();
        state1.insert("key1".to_string(), "value1".to_string());
        state1.insert("key2".to_string(), "value2".to_string());
        store.set_baseline(state1);

        let mut state2 = HashMap::new();
        state2.insert("key1".to_string(), "value1_updated".to_string());
        state2.insert("key2".to_string(), "value2".to_string());
        state2.insert("key3".to_string(), "value3".to_string());
        store.apply_new_state(&state2);

        assert_eq!(store.diff_count(), 1);
        assert_eq!(store.get(&"key1".to_string()), Some("value1_updated".to_string()));
        assert_eq!(store.get(&"key3".to_string()), Some("value3".to_string()));
    }

    #[test]
    fn test_differential_delete() {
        let mut store: DifferentialStore<String, String> = DifferentialStore::new();

        let mut state1 = HashMap::new();
        state1.insert("key1".to_string(), "value1".to_string());
        state1.insert("key2".to_string(), "value2".to_string());
        store.set_baseline(state1);

        let mut state2 = HashMap::new();
        state2.insert("key1".to_string(), "value1".to_string());
        // key2 deleted
        store.apply_new_state(&state2);

        assert_eq!(store.get(&"key2".to_string()), None);
    }

    #[test]
    fn test_compaction() {
        let mut store: DifferentialStore<String, i32> = DifferentialStore::new().with_max_chain(3);

        let mut baseline = HashMap::new();
        baseline.insert("a".to_string(), 1);
        store.set_baseline(baseline);

        for i in 2..=4 {
            let mut state = HashMap::new();
            state.insert("a".to_string(), i);
            store.apply_new_state(&state);
        }

        // Should have compacted after 3 diffs
        assert_eq!(store.diff_count(), 0);
        assert_eq!(store.get(&"a".to_string()), Some(4));
        assert_eq!(store.archived_count(), 1);
    }
}
