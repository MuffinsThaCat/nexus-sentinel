//! Domain Reputation Monitor — tracks domain blacklist/reputation status.
//!
//! Memory optimizations (2 techniques):
//! - **#461 Differential**: Blacklist status changes slowly
//! - **#6 Theoretical Verifier**: Bounded by domain count

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
pub struct DomainReputation {
    pub domain: String,
    pub reputation_score: f64,
    pub blacklisted: bool,
    pub last_checked: i64,
}

/// Domain reputation monitor.
pub struct DomainReputationMonitor {
    domains: RwLock<HashMap<String, DomainReputation>>,
    domain_cache: TieredCache<String, f64>,
    alerts: RwLock<Vec<DarkwebAlert>>,
    total_checked: AtomicU64,
    blacklisted: AtomicU64,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl DomainReputationMonitor {
    pub fn new() -> Self {
        Self {
            domains: RwLock::new(HashMap::new()),
            domain_cache: TieredCache::new(50_000),
            alerts: RwLock::new(Vec::new()),
            total_checked: AtomicU64::new(0),
            blacklisted: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("domain_reputation", 4 * 1024 * 1024);
        self.domain_cache = self.domain_cache.with_metrics(metrics.clone(), "domain_reputation");
        self.metrics = Some(metrics);
        self
    }

    /// Darkweb TLDs that always warrant elevated alerting.
    const DARKWEB_TLDS: &'static [&'static str] = &[".onion", ".i2p", ".bit", ".loki"];

    /// Reputation score thresholds.
    const SCORE_CRITICAL: f64 = 20.0;
    const SCORE_SUSPICIOUS: f64 = 50.0;

    pub fn check_domain(&self, rep: DomainReputation) {
        self.total_checked.fetch_add(1, Ordering::Relaxed);
        let now = rep.last_checked;
        let domain_lower = rep.domain.to_lowercase();
        let is_darkweb = Self::DARKWEB_TLDS.iter().any(|tld| domain_lower.ends_with(tld));

        if rep.blacklisted {
            self.blacklisted.fetch_add(1, Ordering::Relaxed);
            let sev = if is_darkweb { Severity::Critical } else { Severity::High };
            warn!(domain = %rep.domain, score = rep.reputation_score, "Domain blacklisted");
            self.add_alert(now, sev, "Blacklisted domain", &format!("{} is blacklisted (score: {:.1})", rep.domain, rep.reputation_score));
        } else if rep.reputation_score < Self::SCORE_CRITICAL {
            self.add_alert(now, Severity::High, "Very low reputation", &format!("{} score {:.1} (critical threshold)", rep.domain, rep.reputation_score));
        } else if rep.reputation_score < Self::SCORE_SUSPICIOUS {
            self.add_alert(now, Severity::Medium, "Suspicious reputation", &format!("{} score {:.1}", rep.domain, rep.reputation_score));
        }

        if is_darkweb && !rep.blacklisted {
            self.add_alert(now, Severity::High, "Darkweb domain accessed", &format!("{} is a darkweb domain", rep.domain));
        }

        // Detect reputation score drops
        if let Some(prev) = self.domains.read().get(&rep.domain) {
            let delta = rep.reputation_score - prev.reputation_score;
            if delta < -20.0 {
                self.add_alert(now, Severity::High, "Reputation drop", &format!("{} score dropped {:.1} ({:.1} → {:.1})", rep.domain, delta.abs(), prev.reputation_score, rep.reputation_score));
            }
            if !prev.blacklisted && rep.blacklisted {
                self.add_alert(now, Severity::Critical, "Newly blacklisted", &format!("{} was just blacklisted", rep.domain));
            }
        }

        self.domains.write().insert(rep.domain.clone(), rep);
    }

    pub fn get(&self, domain: &str) -> Option<DomainReputation> { self.domains.read().get(domain).cloned() }

    /// Get all blacklisted domains.
    pub fn blacklisted_domains(&self) -> Vec<DomainReputation> {
        self.domains.read().values().filter(|d| d.blacklisted).cloned().collect()
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(DarkwebAlert { timestamp: ts, severity: sev, component: "domain_reputation".into(), title: title.into(), details: details.into() });
    }

    pub fn total_checked(&self) -> u64 { self.total_checked.load(Ordering::Relaxed) }
    pub fn blacklisted(&self) -> u64 { self.blacklisted.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<DarkwebAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
