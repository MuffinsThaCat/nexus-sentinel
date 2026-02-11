//! Telemetry Monitor — Component 8 of 9 in IoT Security Layer
//!
//! Monitors IoT device telemetry streams for health and security.
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Hot telemetry lookups
//! - **#6 Theoretical Verifier**: Bound telemetry store

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use std::collections::HashMap;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TelemetryPoint {
    pub timestamp: i64,
    pub device_id: String,
    pub metric: String,
    pub value: f64,
}

/// Telemetry monitor with 2 memory breakthroughs.
pub struct TelemetryMonitor {
    latest: RwLock<HashMap<String, HashMap<String, f64>>>,
    thresholds: RwLock<HashMap<String, HashMap<String, (f64, f64)>>>,
    /// #2 Tiered cache: hot telemetry lookups
    telemetry_cache: TieredCache<String, f64>,
    alerts: RwLock<Vec<IoTAlert>>,
    total_points: AtomicU64,
    /// #6 Theoretical verifier
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl TelemetryMonitor {
    pub fn new() -> Self {
        Self {
            latest: RwLock::new(HashMap::new()),
            thresholds: RwLock::new(HashMap::new()),
            telemetry_cache: TieredCache::new(100_000),
            alerts: RwLock::new(Vec::new()),
            total_points: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    /// #6 Theoretical verifier: bound telemetry store at 16MB.
    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("telemetry_monitor", 16 * 1024 * 1024);
        self.telemetry_cache = self.telemetry_cache.with_metrics(metrics.clone(), "telemetry_monitor");
        self.metrics = Some(metrics);
        self
    }

    pub fn set_threshold(&self, device_id: &str, metric: &str, min: f64, max: f64) {
        self.thresholds.write()
            .entry(device_id.to_string()).or_default()
            .insert(metric.to_string(), (min, max));
    }

    pub fn ingest(&self, point: TelemetryPoint) -> bool {
        if !self.enabled { return true; }
        self.total_points.fetch_add(1, Ordering::Relaxed);
        let now = point.timestamp;

        self.latest.write()
            .entry(point.device_id.clone()).or_default()
            .insert(point.metric.clone(), point.value);

        // Check thresholds
        let thresholds = self.thresholds.read();
        if let Some(device_thresholds) = thresholds.get(&point.device_id) {
            if let Some(&(min, max)) = device_thresholds.get(&point.metric) {
                if point.value < min || point.value > max {
                    warn!(device = %point.device_id, metric = %point.metric, value = point.value, "Telemetry threshold breach");
                    self.add_alert(now, Severity::High, "Telemetry threshold breach",
                        &format!("Device {} metric {} = {:.2} outside [{:.2}, {:.2}]",
                            point.device_id, point.metric, point.value, min, max),
                        Some(&point.device_id));
                    return false;
                }
            }
        }
        true
    }

    pub fn get_latest(&self, device_id: &str) -> HashMap<String, f64> {
        self.latest.read().get(device_id).cloned().unwrap_or_default()
    }

    fn add_alert(&self, ts: i64, severity: Severity, title: &str, details: &str, device: Option<&str>) {
        let mut alerts = self.alerts.write();
        if alerts.len() >= MAX_ALERTS { alerts.remove(0); }
        alerts.push(IoTAlert {
            timestamp: ts, severity, component: "telemetry_monitor".into(),
            title: title.into(), details: details.into(),
            device_id: device.map(|s| s.to_string()),
        });
    }

    pub fn total_points(&self) -> u64 { self.total_points.load(Ordering::Relaxed) }
    pub fn monitored_devices(&self) -> usize { self.latest.read().len() }
    pub fn alerts(&self) -> Vec<IoTAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, enabled: bool) { self.enabled = enabled; }
}
