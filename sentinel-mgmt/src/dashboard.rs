//! Web Dashboard — serves real-time security status to operators.
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Current view data hot, historical views cold
//! - **#6 Theoretical Verifier**: Bound server memory

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
pub struct DashboardWidget {
    pub widget_id: String,
    pub title: String,
    pub data_source: String,
    pub refresh_secs: u32,
    pub last_updated: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SystemStatus {
    pub component: String,
    pub healthy: bool,
    pub alert_count: u64,
    pub last_check: i64,
}

/// Web dashboard with 2 memory breakthroughs.
pub struct Dashboard {
    widgets: RwLock<HashMap<String, DashboardWidget>>,
    status_cache: RwLock<HashMap<String, SystemStatus>>,
    /// #2 Tiered cache: current view data hot
    view_cache: TieredCache<String, String>,
    alerts: RwLock<Vec<MgmtAlert>>,
    total_views: AtomicU64,
    /// #6 Theoretical verifier
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl Dashboard {
    pub fn new() -> Self {
        Self {
            widgets: RwLock::new(HashMap::new()),
            status_cache: RwLock::new(HashMap::new()),
            view_cache: TieredCache::new(10_000),
            alerts: RwLock::new(Vec::new()),
            total_views: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    /// #6 Theoretical verifier: bound server memory at 4MB.
    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("dashboard", 4 * 1024 * 1024);
        self.view_cache = self.view_cache.with_metrics(metrics.clone(), "dashboard");
        self.metrics = Some(metrics);
        self
    }

    pub fn register_widget(&self, widget: DashboardWidget) {
        self.widgets.write().insert(widget.widget_id.clone(), widget);
    }

    pub fn update_status(&self, status: SystemStatus) {
        if !status.healthy {
            let now = chrono::Utc::now().timestamp();
            warn!(component = %status.component, alerts = status.alert_count, "Unhealthy component");
            self.add_alert(now, Severity::High, "Component unhealthy", &format!("{} is unhealthy", status.component));
        }
        self.status_cache.write().insert(status.component.clone(), status);
    }

    pub fn record_view(&self) { self.total_views.fetch_add(1, Ordering::Relaxed); }

    pub fn get_status(&self, component: &str) -> Option<SystemStatus> {
        self.status_cache.read().get(component).cloned()
    }

    pub fn all_statuses(&self) -> Vec<SystemStatus> {
        self.status_cache.read().values().cloned().collect()
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(MgmtAlert { timestamp: ts, severity: sev, component: "dashboard".into(), title: title.into(), details: details.into() });
    }

    pub fn total_views(&self) -> u64 { self.total_views.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<MgmtAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
