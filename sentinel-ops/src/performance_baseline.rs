//! Performance Baseline — establishes and monitors performance baselines.
//!
//! Memory optimizations (2 techniques):
//! - **#1 Hierarchical State**: Baselines at multiple granularities
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
pub struct BaselineMetric {
    pub component: String,
    pub metric_name: String,
    pub baseline_value: f64,
    pub current_value: f64,
    pub deviation_pct: f64,
    pub measured_at: i64,
}

/// Performance baseline monitor.
pub struct PerformanceBaseline {
    baselines: RwLock<HashMap<String, f64>>,
    readings: RwLock<Vec<BaselineMetric>>,
    baseline_cache: TieredCache<String, f64>,
    alerts: RwLock<Vec<OpsAlert>>,
    total_measured: AtomicU64,
    deviations: AtomicU64,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl PerformanceBaseline {
    pub fn new() -> Self {
        Self {
            baselines: RwLock::new(HashMap::new()),
            readings: RwLock::new(Vec::new()),
            baseline_cache: TieredCache::new(5_000),
            alerts: RwLock::new(Vec::new()),
            total_measured: AtomicU64::new(0),
            deviations: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("performance_baseline", 2 * 1024 * 1024);
        self.baseline_cache = self.baseline_cache.with_metrics(metrics.clone(), "performance_baseline");
        self.metrics = Some(metrics);
        self
    }

    pub fn set_baseline(&self, key: &str, value: f64) {
        self.baselines.write().insert(key.to_string(), value);
    }

    /// Adaptive EMA baseline: auto-learns from first N samples.
    pub fn measure(&self, component: &str, metric: &str, value: f64) -> f64 {
        self.total_measured.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        let key = format!("{}:{}", component, metric);

        // Auto-establish baseline from first reading if not set
        let mut baselines = self.baselines.write();
        let baseline = if let Some(b) = baselines.get(&key).copied() {
            // EMA update: slowly adapt baseline (alpha=0.05)
            let updated = b * 0.95 + value * 0.05;
            baselines.insert(key.clone(), updated);
            b
        } else {
            baselines.insert(key.clone(), value);
            value
        };
        drop(baselines);

        let deviation = if baseline != 0.0 { ((value - baseline) / baseline * 100.0).abs() } else { 0.0 };

        // Tiered severity based on deviation magnitude
        let sev = if deviation > 200.0 {
            Severity::Critical
        } else if deviation > 100.0 {
            Severity::High
        } else if deviation > 50.0 {
            Severity::Medium
        } else {
            Severity::Low
        };

        if deviation > 50.0 {
            self.deviations.fetch_add(1, Ordering::Relaxed);
            warn!(component = %component, metric = %metric, deviation = deviation, "Performance deviation");
            self.add_alert(now, sev, "Performance deviation", &format!("{}:{} deviated {:.1}% (val={:.2} base={:.2})", component, metric, deviation, value, baseline));
        }

        // Detect sudden drops (potential DoS or resource exhaustion)
        if value < baseline * 0.1 && baseline > 0.0 {
            self.add_alert(now, Severity::Critical, "Performance collapse", &format!("{}:{} dropped to {:.1}% of baseline", component, metric, (value / baseline) * 100.0));
        }

        let mut r = self.readings.write();
        if r.len() >= MAX_ALERTS { r.remove(0); }
        r.push(BaselineMetric { component: component.into(), metric_name: metric.into(), baseline_value: baseline, current_value: value, deviation_pct: deviation, measured_at: now });
        deviation
    }

    /// Get a health summary of all tracked metrics.
    pub fn health_summary(&self) -> Vec<(String, f64)> {
        let readings = self.readings.read();
        let mut latest: HashMap<String, f64> = HashMap::new();
        for r in readings.iter().rev() {
            let key = format!("{}:{}", r.component, r.metric_name);
            latest.entry(key).or_insert(r.deviation_pct);
        }
        let mut result: Vec<_> = latest.into_iter().collect();
        result.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        result
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(OpsAlert { timestamp: ts, severity: sev, component: "performance_baseline".into(), title: title.into(), details: details.into() });
    }

    pub fn total_measured(&self) -> u64 { self.total_measured.load(Ordering::Relaxed) }
    pub fn deviations(&self) -> u64 { self.deviations.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<OpsAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
