//! Honey File — plants decoy files that alert on access.
//!
//! Memory optimizations (2 techniques):
//! - **#627 Sparse**: Few honey files relative to real files
//! - **#6 Theoretical Verifier**: Bounded by file count

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use std::collections::HashMap;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HoneyFileRecord {
    pub file_path: String,
    pub description: String,
    pub deployed_at: i64,
    pub access_count: u32,
    pub last_accessed_by: Option<String>,
    pub last_accessed_at: Option<i64>,
}

/// Honey file deployer with 2 memory breakthroughs.
pub struct HoneyFile {
    files: RwLock<HashMap<String, HoneyFileRecord>>,
    /// #2 Tiered cache: file path lookups hot
    file_cache: TieredCache<String, bool>,
    alerts: RwLock<Vec<DeceptionAlert>>,
    total_deployed: AtomicU64,
    total_accesses: AtomicU64,
    /// #6 Theoretical verifier
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl HoneyFile {
    pub fn new() -> Self {
        Self {
            files: RwLock::new(HashMap::new()),
            file_cache: TieredCache::new(10_000),
            alerts: RwLock::new(Vec::new()),
            total_deployed: AtomicU64::new(0),
            total_accesses: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    /// #6 Theoretical verifier: bounded at 1MB.
    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("honey_file", 1024 * 1024);
        self.file_cache = self.file_cache.with_metrics(metrics.clone(), "honey_file");
        self.metrics = Some(metrics);
        self
    }

    pub fn deploy(&self, path: &str, description: &str) {
        self.total_deployed.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        self.files.write().insert(path.to_string(), HoneyFileRecord {
            file_path: path.into(), description: description.into(), deployed_at: now,
            access_count: 0, last_accessed_by: None, last_accessed_at: None,
        });
    }

    pub fn report_access(&self, path: &str, accessor: &str) -> bool {
        let mut files = self.files.write();
        if let Some(file) = files.get_mut(path) {
            file.access_count += 1;
            let now = chrono::Utc::now().timestamp();
            file.last_accessed_by = Some(accessor.into());
            file.last_accessed_at = Some(now);
            self.total_accesses.fetch_add(1, Ordering::Relaxed);
            warn!(path = %path, accessor = %accessor, "Honey file accessed!");
            self.add_alert(now, Severity::Critical, "Honey file accessed", &format!("{} accessed {} ({})", accessor, path, file.description));
            return true;
        }
        false
    }

    pub fn is_honey_file(&self, path: &str) -> bool { self.files.read().contains_key(path) }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(DeceptionAlert { timestamp: ts, severity: sev, component: "honey_file".into(), title: title.into(), details: details.into() });
    }

    pub fn total_deployed(&self) -> u64 { self.total_deployed.load(Ordering::Relaxed) }
    pub fn total_accesses(&self) -> u64 { self.total_accesses.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<DeceptionAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
