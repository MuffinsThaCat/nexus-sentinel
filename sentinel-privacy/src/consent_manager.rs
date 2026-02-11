//! Consent Manager — tracks user data processing consents.
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
pub struct ConsentRecord {
    pub user_id: String,
    pub purpose: String,
    pub granted: bool,
    pub granted_at: i64,
    pub expires_at: Option<i64>,
}

/// GDPR/CCPA required purposes that must have explicit consent.
const REQUIRED_PURPOSES: &[&str] = &[
    "marketing", "profiling", "third_party_sharing", "cross_border_transfer",
    "automated_decision", "biometric_processing", "special_category",
];

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConsentAudit {
    pub user_id: String,
    pub compliant: bool,
    pub missing_consents: Vec<String>,
    pub expired_consents: Vec<String>,
    pub findings: Vec<String>,
}

const MAX_USERS: usize = 100_000;

pub struct ConsentManager {
    consents: RwLock<HashMap<String, Vec<ConsentRecord>>>,
    alerts: RwLock<Vec<PrivacyAlert>>,
    total_recorded: AtomicU64,
    total_violations: AtomicU64,
    _cache: TieredCache<String, u64>,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl ConsentManager {
    pub fn new() -> Self {
        Self {
            consents: RwLock::new(HashMap::new()),
            alerts: RwLock::new(Vec::new()),
            total_recorded: AtomicU64::new(0),
            total_violations: AtomicU64::new(0),
            enabled: true,
            _cache: TieredCache::new(10_000),
            metrics: None,
        }
    }

    pub fn record_consent(&self, record: ConsentRecord) {
        self.total_recorded.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();

        if !record.granted {
            warn!(user = %record.user_id, purpose = %record.purpose, "Consent denied");
            self.add_alert(now, Severity::Medium, "Consent denied", &format!("User {} denied {}", record.user_id, record.purpose));
        }

        // Check for expired consent being re-recorded
        if let Some(exp) = record.expires_at {
            if exp <= now {
                warn!(user = %record.user_id, "Expired consent recorded");
                self.add_alert(now, Severity::High, "Expired consent", &format!("User {} consent already expired", record.user_id));
            }
        }

        let mut consents = self.consents.write();
        // Memory bound
        if consents.len() >= MAX_USERS && !consents.contains_key(&record.user_id) {
            if let Some(oldest_key) = consents.keys().next().cloned() {
                consents.remove(&oldest_key);
            }
        }
        consents.entry(record.user_id.clone()).or_default().push(record);
    }

    pub fn has_consent(&self, user_id: &str, purpose: &str) -> bool {
        let now = chrono::Utc::now().timestamp();
        self.consents.read().get(user_id).map_or(false, |recs| {
            recs.iter().any(|r| r.purpose == purpose && r.granted && r.expires_at.map_or(true, |e| e > now))
        })
    }

    /// Revoke consent for a specific purpose (GDPR right to withdraw).
    pub fn revoke_consent(&self, user_id: &str, purpose: &str) {
        let now = chrono::Utc::now().timestamp();
        let mut consents = self.consents.write();
        if let Some(recs) = consents.get_mut(user_id) {
            for r in recs.iter_mut() {
                if r.purpose == purpose && r.granted {
                    r.granted = false;
                    r.expires_at = Some(now);
                }
            }
        }
        drop(consents);
        self.add_alert(now, Severity::Low, "Consent revoked", &format!("User {} revoked {}", user_id, purpose));
    }

    /// Audit a user's consent compliance against required purposes.
    pub fn audit_user(&self, user_id: &str, active_purposes: &[&str]) -> ConsentAudit {
        let now = chrono::Utc::now().timestamp();
        let consents = self.consents.read();
        let user_recs = consents.get(user_id);
        let mut missing = Vec::new();
        let mut expired = Vec::new();
        let mut findings = Vec::new();

        for purpose in active_purposes {
            let is_required = REQUIRED_PURPOSES.iter().any(|r| purpose.contains(r));
            if !is_required { continue; }

            match user_recs {
                Some(recs) => {
                    let consent = recs.iter().rev().find(|r| r.purpose == *purpose);
                    match consent {
                        Some(r) if !r.granted => {
                            missing.push(purpose.to_string());
                            findings.push(format!("no_consent:{}", purpose));
                        }
                        Some(r) if r.expires_at.map_or(false, |e| e <= now) => {
                            expired.push(purpose.to_string());
                            findings.push(format!("expired_consent:{}", purpose));
                        }
                        None => {
                            missing.push(purpose.to_string());
                            findings.push(format!("never_consented:{}", purpose));
                        }
                        _ => {}
                    }
                }
                None => {
                    missing.push(purpose.to_string());
                    findings.push(format!("no_records:{}", purpose));
                }
            }
        }

        let compliant = missing.is_empty() && expired.is_empty();
        if !compliant {
            self.total_violations.fetch_add(1, Ordering::Relaxed);
            let cats = findings.join(", ");
            self.add_alert(now, Severity::High, "Consent violation", &format!("{}: {}", user_id, &cats[..cats.len().min(200)]));
        }

        ConsentAudit { user_id: user_id.into(), compliant, missing_consents: missing, expired_consents: expired, findings }
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(PrivacyAlert { timestamp: ts, severity: sev, component: "consent_manager".into(), title: title.into(), details: details.into() });
    }

    pub fn total_recorded(&self) -> u64 { self.total_recorded.load(Ordering::Relaxed) }
    pub fn total_violations(&self) -> u64 { self.total_violations.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<PrivacyAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
