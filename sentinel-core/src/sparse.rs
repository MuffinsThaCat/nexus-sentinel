//! Breakthrough #627: Sparse Representation
//!
//! Only store non-zero entries. For security data, most structures are sparse:
//! - Connection matrices (few active of all possible src×dst pairs)
//! - Permission maps (few granted of all possible)
//! - Behavioral baselines (most features at zero/normal)
//! - VLAN assignments, policy matrices, correlation tables
//!
//! Used by ~55 of 203 security components.

use std::collections::HashMap;
use std::hash::Hash;

/// A sparse matrix backed by a HashMap. Only stores non-default entries.
/// Memory usage is O(nnz) where nnz = number of non-zero entries,
/// instead of O(rows × cols) for a dense matrix.
pub struct SparseMatrix<R, C, V> {
    data: HashMap<(R, C), V>,
    default_value: V,
    row_count: usize,
    col_count: usize,
}

impl<R, C, V> SparseMatrix<R, C, V>
where
    R: Eq + Hash + Clone,
    C: Eq + Hash + Clone,
    V: Clone + PartialEq,
{
    pub fn new(default_value: V) -> Self {
        Self {
            data: HashMap::new(),
            default_value,
            row_count: 0,
            col_count: 0,
        }
    }

    pub fn with_capacity(default_value: V, capacity: usize) -> Self {
        Self {
            data: HashMap::with_capacity(capacity),
            default_value,
            row_count: 0,
            col_count: 0,
        }
    }

    /// Set a value. If the value equals the default, removes it (saves memory).
    pub fn set(&mut self, row: R, col: C, value: V) {
        if value == self.default_value {
            self.data.remove(&(row, col));
        } else {
            self.data.insert((row, col), value);
        }
    }

    /// Get a value. Returns the default if not explicitly set.
    pub fn get(&self, row: &R, col: &C) -> &V {
        self.data
            .get(&(row.clone(), col.clone()))
            .unwrap_or(&self.default_value)
    }

    /// Remove an entry (resets to default).
    pub fn remove(&mut self, row: &R, col: &C) -> Option<V> {
        self.data.remove(&(row.clone(), col.clone()))
    }

    /// Number of non-default entries stored.
    pub fn nnz(&self) -> usize {
        self.data.len()
    }

    /// Sparsity ratio: fraction of entries that are default (not stored).
    /// Returns 1.0 if dimensions not set, or actual ratio.
    pub fn sparsity(&self) -> f64 {
        let total = self.row_count * self.col_count;
        if total == 0 {
            return 1.0;
        }
        1.0 - (self.nnz() as f64 / total as f64)
    }

    /// Memory savings vs dense representation.
    /// Returns (sparse_bytes, dense_bytes, ratio).
    pub fn memory_savings(&self) -> (usize, usize, f64) {
        let entry_size = std::mem::size_of::<(R, C)>() + std::mem::size_of::<V>();
        let sparse_bytes = self.nnz() * entry_size;
        let dense_bytes = self.row_count * self.col_count * std::mem::size_of::<V>();
        let ratio = if sparse_bytes > 0 {
            dense_bytes as f64 / sparse_bytes as f64
        } else {
            f64::INFINITY
        };
        (sparse_bytes, dense_bytes, ratio)
    }

    /// Set the logical dimensions (for sparsity calculations only).
    pub fn set_dimensions(&mut self, rows: usize, cols: usize) {
        self.row_count = rows;
        self.col_count = cols;
    }

    /// Iterate over all non-default entries.
    pub fn iter(&self) -> impl Iterator<Item = (&(R, C), &V)> {
        self.data.iter()
    }

    /// Get all non-default entries for a specific row.
    pub fn row_entries(&self, row: &R) -> Vec<(&C, &V)> {
        self.data
            .iter()
            .filter(|((r, _), _)| r == row)
            .map(|((_, c), v)| (c, v))
            .collect()
    }

    pub fn clear(&mut self) {
        self.data.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// A sparse vector — only stores non-default elements.
/// Ideal for behavioral feature vectors where most features are at baseline.
pub struct SparseVec<V> {
    data: HashMap<usize, V>,
    default_value: V,
    logical_len: usize,
}

impl<V> SparseVec<V>
where
    V: Clone + PartialEq,
{
    pub fn new(logical_len: usize, default_value: V) -> Self {
        Self {
            data: HashMap::new(),
            default_value,
            logical_len,
        }
    }

    pub fn set(&mut self, index: usize, value: V) {
        if value == self.default_value {
            self.data.remove(&index);
        } else {
            self.data.insert(index, value);
        }
    }

    pub fn get(&self, index: usize) -> &V {
        self.data.get(&index).unwrap_or(&self.default_value)
    }

    pub fn nnz(&self) -> usize {
        self.data.len()
    }

    pub fn logical_len(&self) -> usize {
        self.logical_len
    }

    pub fn sparsity(&self) -> f64 {
        if self.logical_len == 0 {
            return 1.0;
        }
        1.0 - (self.nnz() as f64 / self.logical_len as f64)
    }

    pub fn iter_nonzero(&self) -> impl Iterator<Item = (&usize, &V)> {
        self.data.iter()
    }

    pub fn clear(&mut self) {
        self.data.clear();
    }
}

/// A sparse set — tracks which elements are "present" in a large universe.
/// E.g., "which of 4 billion possible IPs are currently active?"
pub struct SparseSet<T> {
    data: std::collections::HashSet<T>,
}

impl<T: Eq + Hash + Clone> SparseSet<T> {
    pub fn new() -> Self {
        Self {
            data: std::collections::HashSet::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: std::collections::HashSet::with_capacity(capacity),
        }
    }

    pub fn insert(&mut self, value: T) -> bool {
        self.data.insert(value)
    }

    pub fn contains(&self, value: &T) -> bool {
        self.data.contains(value)
    }

    pub fn remove(&mut self, value: &T) -> bool {
        self.data.remove(value)
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.data.iter()
    }

    pub fn clear(&mut self) {
        self.data.clear();
    }
}

impl<T: Eq + Hash + Clone> Default for SparseSet<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sparse_matrix() {
        let mut m: SparseMatrix<u32, u32, u64> = SparseMatrix::new(0);
        m.set_dimensions(1000, 1000);

        // Only set 10 entries in a 1M-cell matrix
        for i in 0..10 {
            m.set(i, i * 100, i as u64 + 1);
        }

        assert_eq!(m.nnz(), 10);
        assert!(m.sparsity() > 0.99999);
        assert_eq!(*m.get(&0, &0), 1);
        assert_eq!(*m.get(&5, &500), 6);
        assert_eq!(*m.get(&999, &999), 0); // default

        let (sparse, dense, ratio) = m.memory_savings();
        assert!(ratio > 10.0, "Should save >10× vs dense: ratio={}", ratio);
        assert!(sparse < dense);
    }

    #[test]
    fn test_sparse_vec() {
        let mut v: SparseVec<f64> = SparseVec::new(10000, 0.0);
        v.set(42, 3.14);
        v.set(9999, 2.71);

        assert_eq!(v.nnz(), 2);
        assert!(v.sparsity() > 0.999);
        assert_eq!(*v.get(42), 3.14);
        assert_eq!(*v.get(0), 0.0); // default
    }
}
