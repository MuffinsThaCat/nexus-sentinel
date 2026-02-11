//! Service Availability Monitor — monitors security service uptime.
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Active service checks hot
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
pub struct ServiceCheck {
    pub service_name: String,
    pub endpoint: String,
    pub healthy: bool,
    pub response_ms: u64,
    pub checked_at: i64,
}

/// Service availability monitor.
pub struct ServiceAvailability {
    services: RwLock<HashMap<String, ServiceCheck>>,
    check_cache: TieredCache<String, bool>,
    alerts: RwLock<Vec<OpsAlert>>,
    total_checks: AtomicU64,
    failures: AtomicU64,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl ServiceAvailability {
    pub fn new() -> Self {
        Self {
            services: RwLock::new(HashMap::new()),
            check_cache: TieredCache::new(5_000),
            alerts: RwLock::new(Vec::new()),
            total_checks: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("service_availability", 2 * 1024 * 1024);
        self.check_cache = self.check_cache.with_metrics(metrics.clone(), "service_availability");
        self.metrics = Some(metrics);
        self
    }

    /// SLA response time thresholds (ms).
    const LATENCY_WARN_MS: u64 = 500;
    const LATENCY_CRITICAL_MS: u64 = 2000;

    pub fn record_check(&self, check: ServiceCheck) {
        self.total_checks.fetch_add(1, Ordering::Relaxed);
        let now = check.checked_at;

        // Detect state transitions
        let prev = self.services.read().get(&check.service_name).cloned();
        let was_healthy = prev.as_ref().map_or(true, |p| p.healthy);

        if !check.healthy {
            self.failures.fetch_add(1, Ordering::Relaxed);

            // Check consecutive failures for escalation
            let consecutive = if !was_healthy { 2 } else { 1 };
            let sev = if consecutive >= 2 { Severity::Critical } else { Severity::High };

            warn!(service = %check.service_name, endpoint = %check.endpoint, "Service unavailable");
            self.add_alert(now, sev, "Service down", &format!("{} at {} unavailable (consecutive={})", check.service_name, check.endpoint, consecutive));
        } else if !was_healthy {
            // Service recovered
            self.add_alert(now, Severity::Low, "Service recovered", &format!("{} is back online ({}ms)", check.service_name, check.response_ms));
        }

        // Latency degradation
        if check.healthy && check.response_ms > Self::LATENCY_CRITICAL_MS {
            self.add_alert(now, Severity::High, "Critical latency", &format!("{} responding in {}ms (threshold {}ms)", check.service_name, check.response_ms, Self::LATENCY_CRITICAL_MS));
        } else if check.healthy && check.response_ms > Self::LATENCY_WARN_MS {
            self.add_alert(now, Severity::Medium, "High latency", &format!("{} responding in {}ms", check.service_name, check.response_ms));
        }

        self.services.write().insert(check.service_name.clone(), check);
    }

    pub fn all_healthy(&self) -> bool {
        self.services.read().values().all(|s| s.healthy)
    }

    /// Calculate overall availability percentage.
    pub fn availability_pct(&self) -> f64 {
        let total = self.total_checks.load(Ordering::Relaxed);
        let fails = self.failures.load(Ordering::Relaxed);
        if total == 0 { return 100.0; }
        ((total - fails) as f64 / total as f64) * 100.0
    }

    /// Get unhealthy services.
    pub fn unhealthy(&self) -> Vec<ServiceCheck> {
        self.services.read().values().filter(|s| !s.healthy).cloned().collect()
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(OpsAlert { timestamp: ts, severity: sev, component: "service_availability".into(), title: title.into(), details: details.into() });
    }

    pub fn total_checks(&self) -> u64 { self.total_checks.load(Ordering::Relaxed) }
    pub fn failures(&self) -> u64 { self.failures.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<OpsAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
