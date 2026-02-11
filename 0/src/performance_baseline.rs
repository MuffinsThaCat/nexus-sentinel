//! performance_baseline component.
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Hot lookups cached
//! - **#6 Theoretical Verifier**: Bound memory usage

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_ALERTS: usize = 5_000;

/// performance_baseline with memory breakthroughs.
pub struct UperformanceUbaseline {
    alerts: RwLock<Vec<OpsAlert>>,
    /// #2 Tiered cache
    _cache: TieredCache<String, u64>,
    counter: AtomicU64,
    /// #6 Theoretical verifier
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl UperformanceUbaseline {
    pub fn new() -> Self {
        Self {
            alerts: RwLock::new(Vec::new()),
            _cache: TieredCache::new(10_000),
            counter: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    /// #6 Theoretical verifier: bound memory.
    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("performance_baseline", 2 * 1024 * 1024);
        self._cache = self._cache.with_metrics(metrics.clone(), "performance_baseline");
        self.metrics = Some(metrics);
        self
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(OpsAlert { timestamp: ts, severity: sev, component: "performance_baseline".into(), title: title.into(), details: details.into() });
    }

    pub fn counter(&self) -> u64 { self.counter.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<OpsAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
