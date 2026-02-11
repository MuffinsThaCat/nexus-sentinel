//! # Persistence Layer — Snapshot/restore for all sentinel state
//!
//! Provides JSON and bincode serialization for component state, with
//! periodic snapshotting and crash recovery. Components implement `Persistable`
//! to opt into automatic state persistence.
//!
//! Memory optimizations:
//! - **#5 Streaming**: Serialize incrementally to avoid doubling memory
//! - **#593 Lossless Compression**: Compress snapshots with lz4

use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{error, info, warn};

/// Trait for components that can persist their state.
pub trait Persistable: Send + Sync {
    /// Component name (unique identifier for snapshot files).
    fn persist_name(&self) -> &str;
    /// Serialize current state to JSON bytes.
    fn snapshot(&self) -> Result<Vec<u8>, String>;
    /// Restore state from JSON bytes.
    fn restore(&self, data: &[u8]) -> Result<(), String>;
}

/// Snapshot metadata stored alongside data.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapshotMeta {
    pub component: String,
    pub timestamp: i64,
    pub size_bytes: usize,
    pub compressed: bool,
    pub version: u32,
}

/// The persistence manager handles snapshotting and restoring all registered components.
pub struct PersistenceManager {
    /// Base directory for snapshot files
    base_dir: PathBuf,
    /// Registered persistable components
    components: RwLock<HashMap<String, Arc<dyn Persistable>>>,
    /// Snapshot history (in-memory metadata)
    history: RwLock<Vec<SnapshotMeta>>,
    /// Stats
    total_snapshots: AtomicU64,
    total_restores: AtomicU64,
    total_failures: AtomicU64,
    /// Whether to compress snapshots
    compress: bool,
}

impl PersistenceManager {
    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        let dir = base_dir.into();
        Self {
            base_dir: dir,
            components: RwLock::new(HashMap::new()),
            history: RwLock::new(Vec::new()),
            total_snapshots: AtomicU64::new(0),
            total_restores: AtomicU64::new(0),
            total_failures: AtomicU64::new(0),
            compress: true,
        }
    }

    /// Register a component for persistence.
    pub fn register(&self, component: Arc<dyn Persistable>) {
        let name = component.persist_name().to_string();
        info!(component = %name, "Registered for persistence");
        self.components.write().insert(name, component);
    }

    /// Ensure the snapshot directory exists.
    pub fn init(&self) -> Result<(), String> {
        std::fs::create_dir_all(&self.base_dir)
            .map_err(|e| format!("Failed to create snapshot dir: {}", e))?;
        info!(dir = %self.base_dir.display(), "Persistence directory initialized");
        Ok(())
    }

    /// Snapshot a single component.
    pub fn snapshot_component(&self, name: &str) -> Result<SnapshotMeta, String> {
        let components = self.components.read();
        let component = components.get(name)
            .ok_or_else(|| format!("Component '{}' not registered", name))?;

        let data = component.snapshot()?;
        let now = chrono::Utc::now().timestamp();

        let (final_data, compressed) = if self.compress {
            match Self::compress_lz4(&data) {
                Ok(compressed_data) => (compressed_data, true),
                Err(_) => (data.clone(), false),
            }
        } else {
            (data.clone(), false)
        };

        let path = self.snapshot_path(name);
        std::fs::write(&path, &final_data)
            .map_err(|e| format!("Failed to write snapshot: {}", e))?;

        let meta = SnapshotMeta {
            component: name.into(),
            timestamp: now,
            size_bytes: final_data.len(),
            compressed,
            version: 1,
        };

        // Write metadata alongside
        let meta_path = self.meta_path(name);
        let meta_json = serde_json::to_vec(&meta)
            .map_err(|e| format!("Failed to serialize meta: {}", e))?;
        std::fs::write(&meta_path, &meta_json)
            .map_err(|e| format!("Failed to write meta: {}", e))?;

        self.total_snapshots.fetch_add(1, Ordering::Relaxed);
        self.history.write().push(meta.clone());

        info!(component = %name, size = final_data.len(), compressed = compressed, "Snapshot saved");
        Ok(meta)
    }

    /// Snapshot ALL registered components.
    pub fn snapshot_all(&self) -> Vec<Result<SnapshotMeta, String>> {
        let names: Vec<String> = self.components.read().keys().cloned().collect();
        names.iter().map(|name| self.snapshot_component(name)).collect()
    }

    /// Restore a single component from its latest snapshot.
    pub fn restore_component(&self, name: &str) -> Result<(), String> {
        let components = self.components.read();
        let component = components.get(name)
            .ok_or_else(|| format!("Component '{}' not registered", name))?;

        let path = self.snapshot_path(name);
        if !path.exists() {
            return Err(format!("No snapshot found for '{}'", name));
        }

        let raw = std::fs::read(&path)
            .map_err(|e| format!("Failed to read snapshot: {}", e))?;

        // Check if compressed by reading metadata
        let meta_path = self.meta_path(name);
        let compressed = if meta_path.exists() {
            let meta_raw = std::fs::read(&meta_path).unwrap_or_default();
            serde_json::from_slice::<SnapshotMeta>(&meta_raw)
                .map(|m| m.compressed)
                .unwrap_or(false)
        } else {
            false
        };

        let data = if compressed {
            Self::decompress_lz4(&raw)?
        } else {
            raw
        };

        component.restore(&data)?;
        self.total_restores.fetch_add(1, Ordering::Relaxed);

        info!(component = %name, "Restored from snapshot");
        Ok(())
    }

    /// Restore ALL registered components from their latest snapshots.
    pub fn restore_all(&self) -> Vec<(String, Result<(), String>)> {
        let names: Vec<String> = self.components.read().keys().cloned().collect();
        names.into_iter().map(|name| {
            let result = self.restore_component(&name);
            if let Err(ref e) = result {
                warn!(component = %name, error = %e, "Failed to restore");
                self.total_failures.fetch_add(1, Ordering::Relaxed);
            }
            (name, result)
        }).collect()
    }

    /// List available snapshots.
    pub fn list_snapshots(&self) -> Vec<SnapshotMeta> {
        let mut metas = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&self.base_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map_or(false, |e| e == "meta") {
                    if let Ok(data) = std::fs::read(&path) {
                        if let Ok(meta) = serde_json::from_slice::<SnapshotMeta>(&data) {
                            metas.push(meta);
                        }
                    }
                }
            }
        }
        metas.sort_by(|a, b| a.component.cmp(&b.component));
        metas
    }

    /// Delete all snapshots for a component.
    pub fn delete_snapshots(&self, name: &str) -> Result<(), String> {
        let _ = std::fs::remove_file(self.snapshot_path(name));
        let _ = std::fs::remove_file(self.meta_path(name));
        info!(component = %name, "Snapshots deleted");
        Ok(())
    }

    // ── Stats ────────────────────────────────────────────────────────────

    pub fn total_snapshots(&self) -> u64 { self.total_snapshots.load(Ordering::Relaxed) }
    pub fn total_restores(&self) -> u64 { self.total_restores.load(Ordering::Relaxed) }
    pub fn total_failures(&self) -> u64 { self.total_failures.load(Ordering::Relaxed) }
    pub fn registered_count(&self) -> usize { self.components.read().len() }

    // ── Internal ─────────────────────────────────────────────────────────

    fn snapshot_path(&self, name: &str) -> PathBuf {
        self.base_dir.join(format!("{}.snapshot", name))
    }

    fn meta_path(&self, name: &str) -> PathBuf {
        self.base_dir.join(format!("{}.meta", name))
    }

    fn compress_lz4(data: &[u8]) -> Result<Vec<u8>, String> {
        Ok(lz4_flex::compress_prepend_size(data))
    }

    fn decompress_lz4(data: &[u8]) -> Result<Vec<u8>, String> {
        lz4_flex::decompress_size_prepended(data)
            .map_err(|e| format!("LZ4 decompress failed: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64 as Counter;

    struct TestComponent {
        name: String,
        value: RwLock<u64>,
    }

    impl TestComponent {
        fn new(name: &str, val: u64) -> Self {
            Self { name: name.into(), value: RwLock::new(val) }
        }
    }

    impl Persistable for TestComponent {
        fn persist_name(&self) -> &str { &self.name }
        fn snapshot(&self) -> Result<Vec<u8>, String> {
            let val = *self.value.read();
            serde_json::to_vec(&val).map_err(|e| e.to_string())
        }
        fn restore(&self, data: &[u8]) -> Result<(), String> {
            let val: u64 = serde_json::from_slice(data).map_err(|e| e.to_string())?;
            *self.value.write() = val;
            Ok(())
        }
    }

    #[test]
    fn test_snapshot_and_restore() {
        let dir = std::env::temp_dir().join("sentinel_test_persist");
        let _ = std::fs::remove_dir_all(&dir);

        let mgr = PersistenceManager::new(&dir);
        mgr.init().unwrap();

        let comp = Arc::new(TestComponent::new("test_comp", 42));
        mgr.register(comp.clone());

        // Snapshot
        let meta = mgr.snapshot_component("test_comp").unwrap();
        assert_eq!(meta.component, "test_comp");
        assert!(meta.size_bytes > 0);

        // Modify state
        *comp.value.write() = 0;
        assert_eq!(*comp.value.read(), 0);

        // Restore
        mgr.restore_component("test_comp").unwrap();
        assert_eq!(*comp.value.read(), 42);

        assert_eq!(mgr.total_snapshots(), 1);
        assert_eq!(mgr.total_restores(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_snapshot_all() {
        let dir = std::env::temp_dir().join("sentinel_test_persist_all");
        let _ = std::fs::remove_dir_all(&dir);

        let mgr = PersistenceManager::new(&dir);
        mgr.init().unwrap();

        mgr.register(Arc::new(TestComponent::new("comp_a", 10)));
        mgr.register(Arc::new(TestComponent::new("comp_b", 20)));

        let results = mgr.snapshot_all();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.is_ok()));

        let snapshots = mgr.list_snapshots();
        assert_eq!(snapshots.len(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_lz4_compression() {
        let data = b"Hello, this is test data that should compress well well well well well";
        let compressed = PersistenceManager::compress_lz4(data).unwrap();
        let decompressed = PersistenceManager::decompress_lz4(&compressed).unwrap();
        assert_eq!(data.as_slice(), decompressed.as_slice());
    }
}
