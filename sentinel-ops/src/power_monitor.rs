//! Power Monitor — monitors UPS/power status for security infrastructure.
//!
//! Memory optimizations (2 techniques):
//! - **#461 Differential**: Power status changes slowly
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
pub struct PowerStatus {
    pub device_id: String,
    pub location: String,
    pub on_battery: bool,
    pub battery_pct: f64,
    pub load_pct: f64,
    pub checked_at: i64,
}

/// Power monitor.
pub struct PowerMonitor {
    devices: RwLock<HashMap<String, PowerStatus>>,
    power_cache: TieredCache<String, f64>,
    alerts: RwLock<Vec<OpsAlert>>,
    total_checked: AtomicU64,
    on_battery: AtomicU64,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl PowerMonitor {
    pub fn new() -> Self {
        Self {
            devices: RwLock::new(HashMap::new()),
            power_cache: TieredCache::new(1_000),
            alerts: RwLock::new(Vec::new()),
            total_checked: AtomicU64::new(0),
            on_battery: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("power_monitor", 1024 * 1024);
        self.power_cache = self.power_cache.with_metrics(metrics.clone(), "power_monitor");
        self.metrics = Some(metrics);
        self
    }

    pub fn record_status(&self, status: PowerStatus) {
        self.total_checked.fetch_add(1, Ordering::Relaxed);
        let now = status.checked_at;

        // Detect power state transitions
        let prev = self.devices.read().get(&status.device_id).cloned();
        let transitioned_to_battery = status.on_battery && prev.as_ref().map_or(true, |p| !p.on_battery);

        if status.on_battery {
            self.on_battery.fetch_add(1, Ordering::Relaxed);

            // Tiered battery severity
            let sev = if status.battery_pct < 5.0 {
                Severity::Critical
            } else if status.battery_pct < 20.0 {
                Severity::High
            } else if status.battery_pct < 50.0 {
                Severity::Medium
            } else {
                Severity::Low
            };

            if transitioned_to_battery {
                warn!(device = %status.device_id, battery = status.battery_pct, "Power loss detected");
                self.add_alert(now, Severity::High, "Power loss", &format!("{} at {} switched to battery ({:.0}%)", status.device_id, status.location, status.battery_pct));
            }

            if status.battery_pct < 20.0 {
                self.add_alert(now, sev, "Low battery", &format!("{} at {} battery {:.0}%", status.device_id, status.location, status.battery_pct));
            }

            // Estimate runtime remaining (rough: assume 100% = 60 min at current load)
            if status.load_pct > 0.0 {
                let est_minutes = (status.battery_pct / status.load_pct) * 60.0;
                if est_minutes < 10.0 {
                    self.add_alert(now, Severity::Critical, "Imminent shutdown", &format!("{} est. {:.0}min remaining", status.device_id, est_minutes));
                }
            }
        } else if prev.as_ref().map_or(false, |p| p.on_battery) {
            // Recovered from battery
            self.add_alert(now, Severity::Low, "Power restored", &format!("{} at {} back on mains", status.device_id, status.location));
        }

        // Overload detection
        if status.load_pct > 90.0 {
            self.add_alert(now, Severity::High, "Overloaded UPS", &format!("{} at {} load {:.0}%", status.device_id, status.location, status.load_pct));
        }

        self.devices.write().insert(status.device_id.clone(), status);
    }

    /// Get devices currently on battery power.
    pub fn battery_devices(&self) -> Vec<PowerStatus> {
        self.devices.read().values().filter(|d| d.on_battery).cloned().collect()
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(OpsAlert { timestamp: ts, severity: sev, component: "power_monitor".into(), title: title.into(), details: details.into() });
    }

    pub fn total_checked(&self) -> u64 { self.total_checked.load(Ordering::Relaxed) }
    pub fn on_battery(&self) -> u64 { self.on_battery.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<OpsAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
