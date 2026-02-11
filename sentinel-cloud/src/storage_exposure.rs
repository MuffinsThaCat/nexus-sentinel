//! Storage Exposure Monitor — detects publicly exposed cloud storage.
//!
//! Memory optimizations (2 techniques):
//! - **#461 Differential**: Exposure status changes slowly
//! - **#6 Theoretical Verifier**: Bounded

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
pub struct ExposureRecord {
    pub resource_id: String,
    pub resource_type: String,
    pub publicly_accessible: bool,
    pub checked_at: i64,
}

/// Storage exposure monitor.
pub struct StorageExposure {
    records: RwLock<HashMap<String, ExposureRecord>>,
    exposure_cache: TieredCache<String, bool>,
    alerts: RwLock<Vec<CloudAlert>>,
    total_checked: AtomicU64,
    exposed: AtomicU64,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl StorageExposure {
    pub fn new() -> Self {
        Self {
            records: RwLock::new(HashMap::new()),
            exposure_cache: TieredCache::new(10_000),
            alerts: RwLock::new(Vec::new()),
            total_checked: AtomicU64::new(0),
            exposed: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("storage_exposure", 2 * 1024 * 1024);
        self.exposure_cache = self.exposure_cache.with_metrics(metrics.clone(), "storage_exposure");
        self.metrics = Some(metrics);
        self
    }

    /// High-risk resource types that should never be public.
    const CRITICAL_RESOURCE_TYPES: &'static [&'static str] = &[
        "database", "secrets_manager", "key_vault", "iam_policy",
        "config_store", "backup", "snapshot", "encryption_key",
    ];

    pub fn check_resource(&self, record: ExposureRecord) {
        self.total_checked.fetch_add(1, Ordering::Relaxed);
        let now = record.checked_at;
        let rtype_lower = record.resource_type.to_lowercase();
        let is_critical = Self::CRITICAL_RESOURCE_TYPES.iter().any(|c| rtype_lower.contains(c));

        // Check for exposure state transitions
        let prev_exposed = {
            let records = self.records.read();
            records.get(&record.resource_id).map(|r| r.publicly_accessible)
        };

        if record.publicly_accessible {
            self.exposed.fetch_add(1, Ordering::Relaxed);
            let sev = if is_critical { Severity::Critical } else { Severity::High };
            warn!(resource = %record.resource_id, rtype = %record.resource_type, "Publicly exposed cloud storage");
            self.add_alert(now, sev, "Public storage", &format!("{} ({}) is publicly accessible", record.resource_id, record.resource_type));

            if prev_exposed == Some(false) {
                // Was private, now public = regression
                self.add_alert(now, Severity::Critical, "Exposure regression", &format!("{} was private, now publicly exposed", record.resource_id));
            }
        } else if prev_exposed == Some(true) {
            // Was public, now private = remediation
            self.add_alert(now, Severity::Low, "Exposure remediated", &format!("{} is no longer publicly accessible", record.resource_id));
        }

        self.records.write().insert(record.resource_id.clone(), record);
    }

    /// Get all currently exposed resources.
    pub fn exposed_resources(&self) -> Vec<ExposureRecord> {
        self.records.read().values().filter(|r| r.publicly_accessible).cloned().collect()
    }

    /// Exposure rate as percentage.
    pub fn exposure_rate(&self) -> f64 {
        let total = self.records.read().len();
        if total == 0 { return 0.0; }
        let exposed = self.records.read().values().filter(|r| r.publicly_accessible).count();
        (exposed as f64 / total as f64) * 100.0
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(CloudAlert { timestamp: ts, severity: sev, component: "storage_exposure".into(), title: title.into(), details: details.into() });
    }

    pub fn total_checked(&self) -> u64 { self.total_checked.load(Ordering::Relaxed) }
    pub fn exposed(&self) -> u64 { self.exposed.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<CloudAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
