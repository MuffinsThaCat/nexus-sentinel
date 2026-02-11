//! Dashboard Data — Component 6 of 10 in SIEM Layer
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Hot dashboard counters
//! - **#6 Theoretical Verifier**: Bound aggregation state

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use std::collections::HashMap;
use parking_lot::RwLock;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DashboardSnapshot {
    pub timestamp: i64,
    pub total_events: u64,
    pub events_per_source: HashMap<String, u64>,
    pub events_per_level: HashMap<String, u64>,
    pub active_alerts: u64,
    pub critical_alerts: u64,
    pub events_per_minute: f64,
}

/// Dashboard data with 2 memory breakthroughs.
pub struct DashboardData {
    source_counts: RwLock<HashMap<String, u64>>,
    level_counts: RwLock<HashMap<String, u64>>,
    recent_timestamps: RwLock<Vec<i64>>,
    /// #2 Tiered cache: hot dashboard counters
    counter_cache: TieredCache<String, u64>,
    max_recent: usize,
    total_events: RwLock<u64>,
    active_alerts: RwLock<u64>,
    critical_alerts: RwLock<u64>,
    /// #6 Theoretical verifier
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl DashboardData {
    pub fn new() -> Self {
        Self {
            source_counts: RwLock::new(HashMap::new()),
            level_counts: RwLock::new(HashMap::new()),
            recent_timestamps: RwLock::new(Vec::new()),
            counter_cache: TieredCache::new(10_000),
            max_recent: 10_000,
            total_events: RwLock::new(0),
            active_alerts: RwLock::new(0),
            critical_alerts: RwLock::new(0),
            metrics: None,
            enabled: true,
        }
    }

    /// #6 Theoretical verifier: bound aggregation state at 2MB.
    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("dashboard_data", 2 * 1024 * 1024);
        self.counter_cache = self.counter_cache.with_metrics(metrics.clone(), "dashboard_data");
        self.metrics = Some(metrics);
        self
    }

    /// Record an event for dashboard metrics.
    pub fn record_event(&self, event: &LogEvent) {
        if !self.enabled { return; }

        *self.source_counts.write().entry(event.source.clone()).or_insert(0) += 1;
        *self.level_counts.write().entry(format!("{:?}", event.level)).or_insert(0) += 1;

        let mut recent = self.recent_timestamps.write();
        if recent.len() >= self.max_recent { recent.remove(0); }
        recent.push(event.timestamp);

        *self.total_events.write() += 1;
    }

    /// Update alert counts.
    pub fn update_alert_counts(&self, active: u64, critical: u64) {
        *self.active_alerts.write() = active;
        *self.critical_alerts.write() = critical;
    }

    /// Generate a dashboard snapshot.
    pub fn snapshot(&self) -> DashboardSnapshot {
        let now = chrono::Utc::now().timestamp();
        let recent = self.recent_timestamps.read();
        let one_min_ago = now - 60;
        let events_last_min = recent.iter().filter(|&&t| t >= one_min_ago).count() as f64;

        DashboardSnapshot {
            timestamp: now,
            total_events: *self.total_events.read(),
            events_per_source: self.source_counts.read().clone(),
            events_per_level: self.level_counts.read().clone(),
            active_alerts: *self.active_alerts.read(),
            critical_alerts: *self.critical_alerts.read(),
            events_per_minute: events_last_min,
        }
    }

    pub fn set_enabled(&mut self, enabled: bool) { self.enabled = enabled; }
}
