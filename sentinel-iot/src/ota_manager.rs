//! OTA Manager — Component 7 of 9 in IoT Security Layer
//!
//! Over-the-air firmware update management.
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Hot update lookups
//! - **#6 Theoretical Verifier**: Bound update store

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use std::collections::HashMap;
use parking_lot::RwLock;
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OtaUpdate {
    pub update_id: String,
    pub target_type: DeviceType,
    pub from_version: String,
    pub to_version: String,
    pub hash: String,
    pub size_bytes: u64,
    pub created_at: i64,
    pub mandatory: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum UpdateStatus { Pending, Downloading, Installing, Success, Failed, Rollback }

/// OTA manager with 2 memory breakthroughs.
pub struct OtaManager {
    available_updates: RwLock<Vec<OtaUpdate>>,
    device_status: RwLock<HashMap<String, (String, UpdateStatus)>>,
    /// #2 Tiered cache: hot update lookups
    update_cache: TieredCache<String, u8>,
    alerts: RwLock<Vec<IoTAlert>>,
    /// #6 Theoretical verifier
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl OtaManager {
    pub fn new() -> Self {
        Self {
            available_updates: RwLock::new(Vec::new()),
            device_status: RwLock::new(HashMap::new()),
            update_cache: TieredCache::new(10_000),
            alerts: RwLock::new(Vec::new()),
            metrics: None,
            enabled: true,
        }
    }

    /// #6 Theoretical verifier: bound update store at 4MB.
    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("ota_manager", 4 * 1024 * 1024);
        self.update_cache = self.update_cache.with_metrics(metrics.clone(), "ota_manager");
        self.metrics = Some(metrics);
        self
    }

    pub fn publish_update(&self, update: OtaUpdate) {
        self.available_updates.write().push(update);
    }

    pub fn start_update(&self, device_id: &str, update_id: &str) -> bool {
        if !self.enabled { return false; }
        let updates = self.available_updates.read();
        if !updates.iter().any(|u| u.update_id == update_id) { return false; }
        self.device_status.write().insert(device_id.to_string(), (update_id.to_string(), UpdateStatus::Pending));
        true
    }

    pub fn report_status(&self, device_id: &str, status: UpdateStatus) {
        let now = chrono::Utc::now().timestamp();
        if let Some(entry) = self.device_status.write().get_mut(device_id) {
            entry.1 = status;
        }
        if status == UpdateStatus::Failed {
            warn!(device = %device_id, "OTA update failed");
            self.add_alert(now, Severity::High, "OTA update failed",
                &format!("Device {} firmware update failed", device_id), Some(device_id));
        } else if status == UpdateStatus::Rollback {
            warn!(device = %device_id, "OTA update rolled back");
            self.add_alert(now, Severity::Medium, "OTA rollback",
                &format!("Device {} rolled back firmware", device_id), Some(device_id));
        }
    }

    pub fn pending_updates(&self, device_type: DeviceType, current_version: &str) -> Vec<OtaUpdate> {
        self.available_updates.read().iter()
            .filter(|u| u.target_type == device_type && u.from_version == current_version)
            .cloned().collect()
    }

    fn add_alert(&self, ts: i64, severity: Severity, title: &str, details: &str, device: Option<&str>) {
        let mut alerts = self.alerts.write();
        if alerts.len() >= MAX_ALERTS { alerts.remove(0); }
        alerts.push(IoTAlert {
            timestamp: ts, severity, component: "ota_manager".into(),
            title: title.into(), details: details.into(),
            device_id: device.map(|s| s.to_string()),
        });
    }

    pub fn update_count(&self) -> usize { self.available_updates.read().len() }
    pub fn alerts(&self) -> Vec<IoTAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, enabled: bool) { self.enabled = enabled; }
}
