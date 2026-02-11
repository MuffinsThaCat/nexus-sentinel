//! Exposed Service Detector — scans external IPs for unintended services.
//!
//! Memory optimizations (2 techniques):
//! - **#5 Streaming**: Scan external IP, accumulate results
//! - **#6 Theoretical Verifier**: Bounded by port count

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExposedService {
    pub ip: String,
    pub port: u16,
    pub service: String,
    pub expected: bool,
    pub detected_at: i64,
}

/// Exposed service detector.
pub struct ExposedServiceDetector {
    services: RwLock<Vec<ExposedService>>,
    service_cache: TieredCache<String, Vec<u16>>,
    alerts: RwLock<Vec<DarkwebAlert>>,
    total_scanned: AtomicU64,
    unexpected_found: AtomicU64,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl ExposedServiceDetector {
    pub fn new() -> Self {
        Self {
            services: RwLock::new(Vec::new()),
            service_cache: TieredCache::new(10_000),
            alerts: RwLock::new(Vec::new()),
            total_scanned: AtomicU64::new(0),
            unexpected_found: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("exposed_service_detector", 2 * 1024 * 1024);
        self.service_cache = self.service_cache.with_metrics(metrics.clone(), "exposed_service_detector");
        self.metrics = Some(metrics);
        self
    }

    /// High-risk ports that should never be publicly exposed.
    const CRITICAL_PORTS: &'static [u16] = &[
        22, 23, 3389, 5900, 1433, 3306, 5432, 6379, 27017,
        9200, 2181, 8080, 9090, 11211, 5672,
    ];

    /// Services that indicate debug/admin exposure.
    const DEBUG_SERVICES: &'static [&'static str] = &[
        "debug", "admin", "phpmyadmin", "kibana", "grafana",
        "jenkins", "docker", "kubernetes-dashboard",
    ];

    pub fn report_service(&self, svc: ExposedService) {
        self.total_scanned.fetch_add(1, Ordering::Relaxed);
        let now = svc.detected_at;
        let svc_lower = svc.service.to_lowercase();
        let is_critical_port = Self::CRITICAL_PORTS.contains(&svc.port);
        let is_debug = Self::DEBUG_SERVICES.iter().any(|d| svc_lower.contains(d));

        if !svc.expected {
            self.unexpected_found.fetch_add(1, Ordering::Relaxed);
            let sev = if is_critical_port || is_debug { Severity::Critical } else { Severity::High };
            warn!(ip = %svc.ip, port = svc.port, service = %svc.service, "Unexpected exposed service");
            self.add_alert(now, sev, "Exposed service", &format!("{}:{} running {}", svc.ip, svc.port, svc.service));
        } else if is_debug {
            // Even expected debug services warrant a warning
            self.add_alert(now, Severity::Medium, "Debug service exposed", &format!("{}:{} {} is a debug/admin service", svc.ip, svc.port, svc.service));
        }

        let mut s = self.services.write();
        if s.len() >= MAX_ALERTS { s.remove(0); }
        s.push(svc);
    }

    /// Get all unexpected services.
    pub fn unexpected_services(&self) -> Vec<ExposedService> {
        self.services.read().iter().filter(|s| !s.expected).cloned().collect()
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(DarkwebAlert { timestamp: ts, severity: sev, component: "exposed_service_detector".into(), title: title.into(), details: details.into() });
    }

    pub fn total_scanned(&self) -> u64 { self.total_scanned.load(Ordering::Relaxed) }
    pub fn unexpected_found(&self) -> u64 { self.unexpected_found.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<DarkwebAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
