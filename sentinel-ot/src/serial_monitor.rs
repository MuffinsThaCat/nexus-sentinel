//! Serial/RS-485 Monitor — monitors legacy serial communications.
//!
//! Memory optimizations (2 techniques):
//! - **#5 Streaming**: Stream serial data, accumulate protocol state
//! - **#6 Theoretical Verifier**: Bounded by serial link count

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
pub struct SerialEvent {
    pub port: String,
    pub direction: String,
    pub bytes_count: u32,
    pub anomalous: bool,
    pub timestamp: i64,
}

/// Serial monitor.
pub struct SerialMonitor {
    ports: RwLock<HashMap<String, Vec<SerialEvent>>>,
    port_cache: TieredCache<String, u64>,
    alerts: RwLock<Vec<OtAlert>>,
    total_events: AtomicU64,
    anomalies: AtomicU64,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl SerialMonitor {
    pub fn new() -> Self {
        Self {
            ports: RwLock::new(HashMap::new()),
            port_cache: TieredCache::new(1_000),
            alerts: RwLock::new(Vec::new()),
            total_events: AtomicU64::new(0),
            anomalies: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("serial_monitor", 2 * 1024 * 1024);
        self.port_cache = self.port_cache.with_metrics(metrics.clone(), "serial_monitor");
        self.metrics = Some(metrics);
        self
    }

    /// Maximum expected serial payload size (bytes). Oversized = potential buffer overflow.
    const MAX_NORMAL_PAYLOAD: u32 = 4096;

    /// Unusual directions that may indicate protocol abuse.
    const SUSPICIOUS_DIRECTIONS: &'static [&'static str] = &[
        "broadcast", "unknown", "bidirectional",
    ];

    pub fn record_event(&self, event: SerialEvent) {
        self.total_events.fetch_add(1, Ordering::Relaxed);
        let now = event.timestamp;

        if event.anomalous {
            self.anomalies.fetch_add(1, Ordering::Relaxed);
            warn!(port = %event.port, bytes = event.bytes_count, "Anomalous serial traffic");
            self.add_alert(now, Severity::High, "Serial anomaly", &format!("Port {} anomalous traffic ({} bytes)", event.port, event.bytes_count));
        }

        // Oversized payload detection (buffer overflow indicator)
        if event.bytes_count > Self::MAX_NORMAL_PAYLOAD {
            self.add_alert(now, Severity::Critical, "Oversized serial payload", &format!("Port {} received {} bytes (max {})", event.port, event.bytes_count, Self::MAX_NORMAL_PAYLOAD));
        }

        // Suspicious direction
        let dir_lower = event.direction.to_lowercase();
        if Self::SUSPICIOUS_DIRECTIONS.iter().any(|d| dir_lower.contains(d)) {
            self.add_alert(now, Severity::Medium, "Unusual serial direction", &format!("Port {} direction: {}", event.port, event.direction));
        }

        // Detect anomaly bursts on same port
        let recent_anomalies = {
            let ports = self.ports.read();
            ports.get(&event.port).map_or(0, |events| {
                events.iter().rev().take(50).filter(|e| e.anomalous && now - e.timestamp < 300).count()
            })
        };
        if recent_anomalies > 5 {
            self.add_alert(now, Severity::Critical, "Serial anomaly burst", &format!("Port {} has {} anomalies in 5 minutes", event.port, recent_anomalies));
        }

        let mut ports = self.ports.write();
        let list = ports.entry(event.port.clone()).or_insert_with(Vec::new);
        if list.len() >= 1_000 { list.remove(0); }
        list.push(event);
    }

    /// Get ports with anomalous activity.
    pub fn anomalous_ports(&self) -> Vec<String> {
        self.ports.read().iter()
            .filter(|(_, events)| events.iter().any(|e| e.anomalous))
            .map(|(port, _)| port.clone())
            .collect()
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(OtAlert { timestamp: ts, severity: sev, component: "serial_monitor".into(), title: title.into(), details: details.into() });
    }

    pub fn total_events(&self) -> u64 { self.total_events.load(Ordering::Relaxed) }
    pub fn anomalies(&self) -> u64 { self.anomalies.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<OtAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
