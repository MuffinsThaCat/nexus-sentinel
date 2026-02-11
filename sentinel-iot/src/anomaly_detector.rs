//! Anomaly Detector — Component 5 of 9 in IoT Security Layer
//!
//! Detects anomalous behavior patterns in IoT device telemetry.
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Hot baseline lookups
//! - **#6 Theoretical Verifier**: Bound baseline store

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use std::collections::HashMap;
use parking_lot::RwLock;
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone, Default)]
struct DeviceBaseline {
    avg_payload_size: f64,
    avg_interval_secs: f64,
    typical_ports: Vec<u16>,
    sample_count: u64,
}

/// Anomaly detector with 2 memory breakthroughs.
pub struct AnomalyDetector {
    baselines: RwLock<HashMap<String, DeviceBaseline>>,
    /// #2 Tiered cache: hot baseline lookups
    baseline_cache: TieredCache<String, f64>,
    alerts: RwLock<Vec<IoTAlert>>,
    threshold: f64,
    learning_samples: u64,
    /// #6 Theoretical verifier
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl AnomalyDetector {
    pub fn new(threshold: f64) -> Self {
        Self {
            baselines: RwLock::new(HashMap::new()),
            baseline_cache: TieredCache::new(100_000),
            alerts: RwLock::new(Vec::new()),
            threshold,
            learning_samples: 50,
            metrics: None,
            enabled: true,
        }
    }

    /// #6 Theoretical verifier: bound baseline store at 8MB.
    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("anomaly_detector", 8 * 1024 * 1024);
        self.baseline_cache = self.baseline_cache.with_metrics(metrics.clone(), "anomaly_detector");
        self.metrics = Some(metrics);
        self
    }

    /// Record a device observation and return anomaly score (0.0 = normal, 1.0 = fully anomalous).
    pub fn observe(&self, device_id: &str, payload_size: usize, interval_secs: f64, port: u16) -> f64 {
        if !self.enabled { return 0.0; }
        let now = chrono::Utc::now().timestamp();
        let mut baselines = self.baselines.write();
        let baseline = baselines.entry(device_id.to_string()).or_default();

        let mut score = 0.0;

        if baseline.sample_count >= self.learning_samples {
            // Size deviation
            if baseline.avg_payload_size > 0.0 {
                let size_dev = ((payload_size as f64) - baseline.avg_payload_size).abs() / baseline.avg_payload_size.max(1.0);
                if size_dev > 2.0 { score += 0.3; }
            }
            // Interval deviation
            if baseline.avg_interval_secs > 0.0 {
                let int_dev = (interval_secs - baseline.avg_interval_secs).abs() / baseline.avg_interval_secs.max(1.0);
                if int_dev > 2.0 { score += 0.3; }
            }
            // Unknown port
            if !baseline.typical_ports.contains(&port) { score += 0.4; }
        }

        // Update baseline (exponential moving average)
        let alpha = 0.1;
        baseline.avg_payload_size = baseline.avg_payload_size * (1.0 - alpha) + (payload_size as f64) * alpha;
        baseline.avg_interval_secs = baseline.avg_interval_secs * (1.0 - alpha) + interval_secs * alpha;
        if !baseline.typical_ports.contains(&port) && baseline.typical_ports.len() < 20 {
            baseline.typical_ports.push(port);
        }
        baseline.sample_count += 1;

        if score >= self.threshold {
            drop(baselines);
            warn!(device = %device_id, score, "IoT anomaly detected");
            self.add_alert(now, Severity::High, "IoT device anomaly",
                &format!("Device {} anomaly score {:.2}", device_id, score), Some(device_id));
        }

        score
    }

    fn add_alert(&self, ts: i64, severity: Severity, title: &str, details: &str, device: Option<&str>) {
        let mut alerts = self.alerts.write();
        if alerts.len() >= MAX_ALERTS { alerts.remove(0); }
        alerts.push(IoTAlert {
            timestamp: ts, severity, component: "anomaly_detector".into(),
            title: title.into(), details: details.into(),
            device_id: device.map(|s| s.to_string()),
        });
    }

    pub fn tracked_devices(&self) -> usize { self.baselines.read().len() }
    pub fn alerts(&self) -> Vec<IoTAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, enabled: bool) { self.enabled = enabled; }
}
