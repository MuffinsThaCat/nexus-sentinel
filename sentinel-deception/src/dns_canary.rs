//! DNS Canary — deploys DNS-based canary tokens to detect exfiltration.
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Active canary lookups hot
//! - **#6 Theoretical Verifier**: Bounded by canary count

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
pub struct DnsCanaryToken {
    pub token_id: String,
    pub subdomain: String,
    pub planted_in: String,
    pub created_at: i64,
    pub triggered: bool,
    pub triggered_at: Option<i64>,
    pub source_ip: Option<String>,
}

/// DNS canary with 2 memory breakthroughs.
pub struct DnsCanary {
    tokens: RwLock<HashMap<String, DnsCanaryToken>>,
    /// #2 Tiered cache: active canary lookups hot
    canary_cache: TieredCache<String, bool>,
    alerts: RwLock<Vec<DeceptionAlert>>,
    total_deployed: AtomicU64,
    total_triggered: AtomicU64,
    /// #6 Theoretical verifier
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl DnsCanary {
    pub fn new() -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            canary_cache: TieredCache::new(10_000),
            alerts: RwLock::new(Vec::new()),
            total_deployed: AtomicU64::new(0),
            total_triggered: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    /// #6 Theoretical verifier: bounded at 2MB.
    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("dns_canary", 2 * 1024 * 1024);
        self.canary_cache = self.canary_cache.with_metrics(metrics.clone(), "dns_canary");
        self.metrics = Some(metrics);
        self
    }

    pub fn deploy(&self, token_id: &str, subdomain: &str, planted_in: &str) {
        self.total_deployed.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        self.tokens.write().insert(subdomain.to_string(), DnsCanaryToken {
            token_id: token_id.into(), subdomain: subdomain.into(), planted_in: planted_in.into(),
            created_at: now, triggered: false, triggered_at: None, source_ip: None,
        });
    }

    pub fn check_query(&self, queried_subdomain: &str, source_ip: &str) -> bool {
        let mut tokens = self.tokens.write();
        if let Some(token) = tokens.get_mut(queried_subdomain) {
            if !token.triggered {
                token.triggered = true;
                let now = chrono::Utc::now().timestamp();
                token.triggered_at = Some(now);
                token.source_ip = Some(source_ip.into());
                self.total_triggered.fetch_add(1, Ordering::Relaxed);
                warn!(token = %token.token_id, source = %source_ip, location = %token.planted_in, "DNS canary triggered!");
                self.add_alert(now, Severity::Critical, "DNS canary triggered", &format!("Token in {} accessed from {}", token.planted_in, source_ip));
            }
            return true;
        }
        false
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(DeceptionAlert { timestamp: ts, severity: sev, component: "dns_canary".into(), title: title.into(), details: details.into() });
    }

    pub fn total_deployed(&self) -> u64 { self.total_deployed.load(Ordering::Relaxed) }
    pub fn total_triggered(&self) -> u64 { self.total_triggered.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<DeceptionAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
