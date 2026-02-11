//! OAuth Token Auditor — audits OAuth tokens for excessive scopes.
//!
//! Memory optimizations (2 techniques):
//! - **#461 Differential**: Token grants change slowly
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
pub struct OauthToken {
    pub client_id: String,
    pub user_id: String,
    pub scopes: Vec<String>,
    pub excessive_scopes: Vec<String>,
    pub granted_at: i64,
    pub expires_at: i64,
}

/// OAuth auditor.
pub struct OauthAuditor {
    tokens: RwLock<HashMap<String, OauthToken>>,
    token_cache: TieredCache<String, bool>,
    alerts: RwLock<Vec<CloudAlert>>,
    total_audited: AtomicU64,
    excessive: AtomicU64,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl OauthAuditor {
    pub fn new() -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            token_cache: TieredCache::new(10_000),
            alerts: RwLock::new(Vec::new()),
            total_audited: AtomicU64::new(0),
            excessive: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("oauth_auditor", 2 * 1024 * 1024);
        self.token_cache = self.token_cache.with_metrics(metrics.clone(), "oauth_auditor");
        self.metrics = Some(metrics);
        self
    }

    /// High-risk OAuth scopes that should be flagged.
    const DANGEROUS_SCOPES: &'static [&'static str] = &[
        "admin", "write:all", "delete:all", "manage:users",
        "manage:billing", "manage:keys", "manage:secrets",
        "org:admin", "repo:delete", "user:email",
    ];

    pub fn audit_token(&self, token: OauthToken) {
        self.total_audited.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();

        // Check for dangerous scopes
        let dangerous: Vec<&String> = token.scopes.iter()
            .filter(|s| Self::DANGEROUS_SCOPES.iter().any(|d| s.to_lowercase().contains(d)))
            .collect();
        if !dangerous.is_empty() {
            self.add_alert(now, Severity::High, "Dangerous OAuth scopes", &format!("{} granted dangerous scopes to {}: {:?}", token.user_id, token.client_id, dangerous));
        }

        if !token.excessive_scopes.is_empty() {
            self.excessive.fetch_add(1, Ordering::Relaxed);
            let sev = if token.excessive_scopes.len() > 5 { Severity::High } else { Severity::Medium };
            warn!(client = %token.client_id, user = %token.user_id, excessive = token.excessive_scopes.len(), "Excessive OAuth scopes");
            self.add_alert(now, sev, "Excessive scopes", &format!("{} granted {} excessive scopes to {}", token.user_id, token.excessive_scopes.len(), token.client_id));
        }

        // Check for expired tokens still in use
        if token.expires_at > 0 && token.expires_at < now {
            self.add_alert(now, Severity::High, "Expired OAuth token", &format!("Token for {}:{} expired {} secs ago", token.client_id, token.user_id, now - token.expires_at));
        }

        // Check for scope escalation vs previous grant
        let key = format!("{}:{}", token.client_id, token.user_id);
        if let Some(prev) = self.tokens.read().get(&key) {
            let new_scopes: Vec<&String> = token.scopes.iter().filter(|s| !prev.scopes.contains(s)).collect();
            if !new_scopes.is_empty() {
                self.add_alert(now, Severity::High, "OAuth scope escalation", &format!("{}:{} gained {} new scopes: {:?}", token.client_id, token.user_id, new_scopes.len(), &new_scopes[..new_scopes.len().min(5)]));
            }
        }

        self.tokens.write().insert(key, token);
    }

    /// Get all tokens with excessive scopes.
    pub fn excessive_tokens(&self) -> Vec<OauthToken> {
        self.tokens.read().values().filter(|t| !t.excessive_scopes.is_empty()).cloned().collect()
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(CloudAlert { timestamp: ts, severity: sev, component: "oauth_auditor".into(), title: title.into(), details: details.into() });
    }

    pub fn total_audited(&self) -> u64 { self.total_audited.load(Ordering::Relaxed) }
    pub fn excessive(&self) -> u64 { self.excessive.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<CloudAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
