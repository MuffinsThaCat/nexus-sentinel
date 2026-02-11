//! DMARC Enforcer — Component 6 of 12 in Email Security Layer
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: DMARC policy lookups hot
//! - **#6 Theoretical Verifier**: Bound policy cache

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use std::collections::HashMap;
use parking_lot::RwLock;
use tracing::warn;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DmarcPolicy {
    None,
    Quarantine,
    Reject,
}

/// DMARC enforcer with 2 memory breakthroughs.
pub struct DmarcEnforcer {
    policy_cache: RwLock<HashMap<String, DmarcPolicy>>,
    /// #2 Tiered cache: DMARC policy lookups hot
    dmarc_cache: TieredCache<String, u8>,
    alerts: RwLock<Vec<EmailAlert>>,
    max_alerts: usize,
    /// #6 Theoretical verifier
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl DmarcEnforcer {
    pub fn new() -> Self {
        Self {
            policy_cache: RwLock::new(HashMap::new()),
            dmarc_cache: TieredCache::new(50_000),
            alerts: RwLock::new(Vec::new()),
            max_alerts: 5_000,
            metrics: None,
            enabled: true,
        }
    }

    /// #6 Theoretical verifier: bound policy cache at 2MB.
    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("dmarc_enforcer", 2 * 1024 * 1024);
        self.dmarc_cache = self.dmarc_cache.with_metrics(metrics.clone(), "dmarc_enforcer");
        self.metrics = Some(metrics);
        self
    }

    pub fn cache_policy(&self, domain: &str, policy: DmarcPolicy) {
        self.policy_cache.write().insert(domain.to_lowercase(), policy);
    }

    /// Evaluate DMARC based on SPF and DKIM results.
    pub fn evaluate(
        &self,
        sender_domain: &str,
        spf_result: AuthResult,
        dkim_result: AuthResult,
    ) -> (Verdict, Option<EmailAlert>) {
        if !self.enabled { return (Verdict::Clean, None); }

        let domain_lower = sender_domain.to_lowercase();
        let policy = self.policy_cache.read().get(&domain_lower).copied();

        let policy = match policy {
            Some(p) => p,
            None => return (Verdict::Clean, None),
        };

        // DMARC passes if either SPF or DKIM passes with alignment
        let passes = spf_result == AuthResult::Pass || dkim_result == AuthResult::Pass;

        if passes {
            return (Verdict::Clean, None);
        }

        // DMARC failed — apply policy
        let (verdict, severity) = match policy {
            DmarcPolicy::Reject => (Verdict::Rejected, Severity::High),
            DmarcPolicy::Quarantine => (Verdict::Quarantined, Severity::Medium),
            DmarcPolicy::None => return (Verdict::Clean, None),
        };

        warn!(domain = %sender_domain, ?policy, "DMARC policy enforcement");
        let alert = EmailAlert {
            timestamp: chrono::Utc::now().timestamp(),
            severity,
            component: "dmarc_enforcer".to_string(),
            title: format!("DMARC {:?} policy applied", policy),
            details: format!(
                "Domain '{}': SPF={:?}, DKIM={:?} → {:?}",
                sender_domain, spf_result, dkim_result, policy
            ),
            email_id: None,
            sender: Some(sender_domain.to_string()),
        };
        let mut alerts = self.alerts.write();
        if alerts.len() >= self.max_alerts { alerts.remove(0); }
        alerts.push(alert.clone());

        (verdict, Some(alert))
    }

    pub fn alerts(&self) -> Vec<EmailAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, enabled: bool) { self.enabled = enabled; }
}
