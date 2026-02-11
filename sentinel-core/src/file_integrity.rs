//! # File Integrity Monitor — Real hash-based change detection
//!
//! Watches critical filesystem paths, computes BLAKE3 hashes, and detects
//! unauthorized modifications, additions, and deletions.

use crate::event_bus::{EventBus, EventSeverity};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{info, warn, error};

/// A file integrity record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileRecord {
    pub path: String,
    pub hash: String,
    pub size: u64,
    pub modified: i64,
    pub permissions: u32,
}

/// Type of integrity violation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum IntegrityViolation {
    Modified { path: String, old_hash: String, new_hash: String },
    Created { path: String, hash: String },
    Deleted { path: String, old_hash: String },
    PermissionChanged { path: String, old_perms: u32, new_perms: u32 },
}

/// File integrity monitor with BLAKE3 hashing.
pub struct FileIntegrityMonitor {
    watched_paths: RwLock<Vec<PathBuf>>,
    baseline: Arc<RwLock<HashMap<String, FileRecord>>>,
    violations: RwLock<Vec<IntegrityViolation>>,
    running: Arc<AtomicBool>,
    scans_completed: AtomicU64,
    violations_found: AtomicU64,
    files_tracked: AtomicU64,
}

impl FileIntegrityMonitor {
    pub fn new() -> Self {
        Self {
            watched_paths: RwLock::new(Vec::new()),
            baseline: Arc::new(RwLock::new(HashMap::new())),
            violations: RwLock::new(Vec::new()),
            running: Arc::new(AtomicBool::new(false)),
            scans_completed: AtomicU64::new(0),
            violations_found: AtomicU64::new(0),
            files_tracked: AtomicU64::new(0),
        }
    }

    /// Add a path to monitor (file or directory).
    pub fn watch(&self, path: &str) {
        self.watched_paths.write().push(PathBuf::from(path));
    }

    /// Add common system paths for monitoring.
    pub fn watch_system_paths(&self) {
        let paths = if cfg!(target_os = "macos") {
            vec!["/etc", "/usr/local/bin", "/Applications"]
        } else {
            vec!["/etc", "/usr/bin", "/usr/sbin", "/boot"]
        };
        let mut wp = self.watched_paths.write();
        for p in paths {
            if Path::new(p).exists() {
                wp.push(PathBuf::from(p));
            }
        }
    }

    /// Build baseline hashes for all watched paths.
    pub fn build_baseline(&self) -> usize {
        let paths = self.watched_paths.read().clone();
        let mut baseline = self.baseline.write();
        baseline.clear();

        for path in &paths {
            self.scan_path_recursive(path, &mut baseline);
        }

        let count = baseline.len();
        self.files_tracked.store(count as u64, Ordering::Relaxed);
        info!(files = count, "File integrity baseline built");
        count
    }

    /// Scan against baseline and return violations.
    pub fn scan(&self) -> Vec<IntegrityViolation> {
        self.scans_completed.fetch_add(1, Ordering::Relaxed);
        let paths = self.watched_paths.read().clone();
        let baseline = self.baseline.read();
        let mut current: HashMap<String, FileRecord> = HashMap::new();
        let mut violations = Vec::new();

        for path in &paths {
            self.scan_path_recursive(path, &mut current);
        }

        // Check for modifications and deletions
        for (path, old_record) in baseline.iter() {
            match current.get(path) {
                Some(new_record) => {
                    if old_record.hash != new_record.hash {
                        violations.push(IntegrityViolation::Modified {
                            path: path.clone(),
                            old_hash: old_record.hash.clone(),
                            new_hash: new_record.hash.clone(),
                        });
                    }
                    #[cfg(unix)]
                    if old_record.permissions != new_record.permissions {
                        violations.push(IntegrityViolation::PermissionChanged {
                            path: path.clone(),
                            old_perms: old_record.permissions,
                            new_perms: new_record.permissions,
                        });
                    }
                }
                None => {
                    violations.push(IntegrityViolation::Deleted {
                        path: path.clone(),
                        old_hash: old_record.hash.clone(),
                    });
                }
            }
        }

        // Check for new files
        for (path, record) in &current {
            if !baseline.contains_key(path) {
                violations.push(IntegrityViolation::Created {
                    path: path.clone(),
                    hash: record.hash.clone(),
                });
            }
        }

        self.violations_found.fetch_add(violations.len() as u64, Ordering::Relaxed);
        let mut v = self.violations.write();
        v.extend(violations.clone());
        // Keep bounded
        let vlen = v.len();
        if vlen > 10_000 { v.drain(..vlen - 10_000); }

        violations
    }

    /// Start periodic integrity scanning.
    pub fn start_periodic(&self, interval_secs: u64, bus: Arc<EventBus>) {
        self.running.store(true, Ordering::Relaxed);
        let running = self.running.clone();
        let baseline = self.baseline.clone();
        let watched = self.watched_paths.read().clone();

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            while running.load(Ordering::Relaxed) {
                ticker.tick().await;

                let bl = baseline.read().clone();
                let mut current: HashMap<String, FileRecord> = HashMap::new();

                for path in &watched {
                    scan_path_into(path, &mut current);
                }

                let mut violation_count = 0u64;
                for (path, old) in &bl {
                    if let Some(new) = current.get(path) {
                        if old.hash != new.hash {
                            violation_count += 1;
                            let mut details = HashMap::new();
                            details.insert("path".into(), path.clone());
                            details.insert("old_hash".into(), old.hash.clone());
                            details.insert("new_hash".into(), new.hash.clone());
                            bus.emit_detection(
                                "file_integrity", "sentinel-endpoint",
                                EventSeverity::Critical, "File modified",
                                details, vec!["integrity".into(), "endpoint".into()],
                            );
                        }
                    } else {
                        violation_count += 1;
                        let mut details = HashMap::new();
                        details.insert("path".into(), path.clone());
                        bus.emit_detection(
                            "file_integrity", "sentinel-endpoint",
                            EventSeverity::High, "File deleted",
                            details, vec!["integrity".into(), "endpoint".into()],
                        );
                    }
                }

                for path in current.keys() {
                    if !bl.contains_key(path) {
                        violation_count += 1;
                        let mut details = HashMap::new();
                        details.insert("path".into(), path.clone());
                        bus.emit_detection(
                            "file_integrity", "sentinel-endpoint",
                            EventSeverity::Medium, "New file detected",
                            details, vec!["integrity".into(), "endpoint".into()],
                        );
                    }
                }

                if violation_count > 0 {
                    warn!(violations = violation_count, "File integrity violations detected");
                }
            }
        });
    }

    fn scan_path_recursive(&self, path: &Path, records: &mut HashMap<String, FileRecord>) {
        scan_path_into(path, records);
    }

    pub fn stop(&self) { self.running.store(false, Ordering::Relaxed); }
    pub fn scans_completed(&self) -> u64 { self.scans_completed.load(Ordering::Relaxed) }
    pub fn violations_found(&self) -> u64 { self.violations_found.load(Ordering::Relaxed) }
    pub fn files_tracked(&self) -> u64 { self.files_tracked.load(Ordering::Relaxed) }
    pub fn violations(&self) -> Vec<IntegrityViolation> { self.violations.read().clone() }
}

/// Recursively scan a path and hash all files.
fn scan_path_into(path: &Path, records: &mut HashMap<String, FileRecord>) {
    if path.is_file() {
        if let Some(record) = hash_file(path) {
            records.insert(path.display().to_string(), record);
        }
    } else if path.is_dir() {
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file() {
                    if let Some(record) = hash_file(&p) {
                        records.insert(p.display().to_string(), record);
                    }
                } else if p.is_dir() {
                    scan_path_into(&p, records);
                }
            }
        }
    }
}

/// Hash a single file with BLAKE3.
fn hash_file(path: &Path) -> Option<FileRecord> {
    let metadata = std::fs::metadata(path).ok()?;
    let data = std::fs::read(path).ok()?;
    let hash = blake3::hash(&data).to_hex().to_string();

    let modified = metadata.modified().ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    #[cfg(unix)]
    let permissions = {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode()
    };
    #[cfg(not(unix))]
    let permissions = 0u32;

    Some(FileRecord {
        path: path.display().to_string(),
        hash,
        size: metadata.len(),
        modified,
        permissions,
    })
}
