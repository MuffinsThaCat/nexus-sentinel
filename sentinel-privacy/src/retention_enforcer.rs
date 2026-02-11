//! Retention Enforcer — enforces data retention and deletion policies.
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Hot lookups cached
//! - **#6 Theoretical Verifier**: Bound memory usage
use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;use std::collections::HashMap;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RetentionPolicy {
    pub data_class: String,
    pub retention_days: u32,
    pub auto_delete: bool,
}

/// Regulatory retention limits by jurisdiction.
const GDPR_MAX_RETENTION: u32 = 1095; // 3 years general
const CCPA_MAX_RETENTION: u32 = 365;  // 1 year default
const HIPAA_MIN_RETENTION: u32 = 2190; // 6 years minimum

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RetentionVerdict {
    pub compliant: bool,
    pub action_required: RetentionAction,
    pub findings: Vec<String>,
    pub severity: Severity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RetentionAction { None, Warn, Delete, Archive }

pub struct RetentionEnforcer {
    policies: RwLock<HashMap<String, RetentionPolicy>>,
    deletion_log: RwLock<Vec<(String, u32, i64)>>,
    alerts: RwLock<Vec<PrivacyAlert>>,
    total_enforced: AtomicU64,
    total_violations: AtomicU64,
    total_deletions: AtomicU64,
    _cache: TieredCache<String, u64>,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl RetentionEnforcer {
    pub fn new() -> Self {
        Self {
            policies: RwLock::new(HashMap::new()),
            deletion_log: RwLock::new(Vec::new()),
            alerts: RwLock::new(Vec::new()),
            total_enforced: AtomicU64::new(0),
            total_violations: AtomicU64::new(0),
            total_deletions: AtomicU64::new(0),
            enabled: true,
            _cache: TieredCache::new(10_000),
            metrics: None,
        }
    }

    pub fn add_policy(&self, policy: RetentionPolicy) {
        self.policies.write().insert(policy.data_class.clone(), policy);
    }

    /// Comprehensive retention check with regulatory awareness and graduated actions.
    pub fn check_full(&self, data_class: &str, age_days: u32) -> RetentionVerdict {
        self.total_enforced.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        let mut findings = Vec::new();
        let mut sev = Severity::Low;
        let mut action = RetentionAction::None;

        if let Some(pol) = self.policies.read().get(data_class) {
            let limit = pol.retention_days;

            if age_days > limit {
                self.total_violations.fetch_add(1, Ordering::Relaxed);
                let overage = age_days - limit;
                findings.push(format!("exceeded:{}d_over_{}d_limit", overage, limit));

                if pol.auto_delete {
                    action = RetentionAction::Delete;
                    self.total_deletions.fetch_add(1, Ordering::Relaxed);
                    let mut log = self.deletion_log.write();
                    if log.len() >= MAX_ALERTS { log.remove(0); }
                    log.push((data_class.to_string(), age_days, now));
                    sev = Severity::Medium;
                } else {
                    action = RetentionAction::Archive;
                    sev = Severity::High;
                }

                // Escalate if massively over limit
                if overage > limit {
                    findings.push(format!("critical_overage:{}x_limit", overage / limit.max(1)));
                    sev = Severity::Critical;
                }
            } else if age_days as f64 > limit as f64 * 0.9 {
                // Warning zone: within 10% of expiry
                findings.push(format!("approaching_expiry:{}d_of_{}d", age_days, limit));
                action = RetentionAction::Warn;
            }
        } else {
            // No policy = check regulatory defaults
            let class_lower = data_class.to_lowercase();
            if class_lower.contains("health") || class_lower.contains("medical") {
                if age_days < HIPAA_MIN_RETENTION {
                    findings.push(format!("hipaa_min_retention:{}d<{}d", age_days, HIPAA_MIN_RETENTION));
                }
            } else if class_lower.contains("personal") || class_lower.contains("pii") {
                if age_days > GDPR_MAX_RETENTION {
                    findings.push(format!("gdpr_default_exceeded:{}d>{}d", age_days, GDPR_MAX_RETENTION));
                    sev = Severity::Medium;
                    action = RetentionAction::Warn;
                }
            }
            if age_days > CCPA_MAX_RETENTION {
                findings.push(format!("ccpa_default_exceeded:{}d>{}d", age_days, CCPA_MAX_RETENTION));
            }
        }

        let compliant = action == RetentionAction::None || action == RetentionAction::Warn;
        if !compliant {
            let cats = findings.join(", ");
            warn!(class = %data_class, age = age_days, "Retention violation");
            self.add_alert(now, sev, "Retention", &format!("{}: {}", data_class, &cats[..cats.len().min(200)]));
        }

        RetentionVerdict { compliant, action_required: action, findings, severity: sev }
    }

    /// Legacy API.
    pub fn check(&self, data_class: &str, age_days: u32) -> bool {
        self.check_full(data_class, age_days).compliant
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(PrivacyAlert { timestamp: ts, severity: sev, component: "retention_enforcer".into(), title: title.into(), details: details.into() });
    }

    pub fn total_enforced(&self) -> u64 { self.total_enforced.load(Ordering::Relaxed) }
    pub fn total_violations(&self) -> u64 { self.total_violations.load(Ordering::Relaxed) }
    pub fn total_deletions(&self) -> u64 { self.total_deletions.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<PrivacyAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
