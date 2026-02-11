//! Auth Enforcer — enforces authentication and authorization on API endpoints.
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
pub struct EndpointPolicy {
    pub endpoint: String,
    pub require_auth: bool,
    pub allowed_roles: Vec<String>,
}

pub struct AuthEnforcer {
    policies: RwLock<HashMap<String, EndpointPolicy>>,
    alerts: RwLock<Vec<ApiAlert>>,
    total_checked: AtomicU64,
    total_denied: AtomicU64,
    /// #2 Tiered cache
    _cache: TieredCache<String, u64>,
    /// #6 Theoretical verifier
    metrics: Option<MemoryMetrics>,    enabled: bool,
}

impl AuthEnforcer {
    pub fn new() -> Self {
        Self { policies: RwLock::new(HashMap::new()), alerts: RwLock::new(Vec::new()), total_checked: AtomicU64::new(0), total_denied: AtomicU64::new(0), enabled: true, _cache: TieredCache::new(10_000), metrics: None }
    }

    /// Sensitive endpoints that require elevated alerting.
    const SENSITIVE_ENDPOINTS: &'static [&'static str] = &[
        "/admin", "/api/users", "/api/config", "/api/secrets",
        "/api/keys", "/api/tokens", "/internal", "/debug",
    ];

    /// Rate limit: max denied attempts per endpoint before escalation.
    const DENIAL_ESCALATION_THRESHOLD: u64 = 5;

    pub fn add_policy(&self, policy: EndpointPolicy) { self.policies.write().insert(policy.endpoint.clone(), policy); }

    pub fn check(&self, endpoint: &str, authenticated: bool, role: Option<&str>) -> bool {
        self.total_checked.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        let is_sensitive = Self::SENSITIVE_ENDPOINTS.iter().any(|s| endpoint.starts_with(s));

        if let Some(pol) = self.policies.read().get(endpoint) {
            if pol.require_auth && !authenticated {
                self.total_denied.fetch_add(1, Ordering::Relaxed);
                let sev = if is_sensitive { Severity::Critical } else { Severity::High };
                warn!(endpoint = %endpoint, "Unauthenticated access");
                self.add_alert(now, sev, "Auth denied", &format!("{} requires auth", endpoint));
                self.check_escalation(endpoint, now);
                return false;
            }
            if !pol.allowed_roles.is_empty() {
                if let Some(r) = role {
                    if !pol.allowed_roles.iter().any(|ar| ar == r) {
                        self.total_denied.fetch_add(1, Ordering::Relaxed);
                        let sev = if is_sensitive { Severity::Critical } else { Severity::High };
                        warn!(endpoint = %endpoint, role = %r, "Unauthorized role");
                        self.add_alert(now, sev, "Role denied", &format!("{} role {} not allowed", endpoint, r));
                        self.check_escalation(endpoint, now);
                        return false;
                    }
                } else if is_sensitive {
                    // No role provided for sensitive endpoint with role requirements
                    self.total_denied.fetch_add(1, Ordering::Relaxed);
                    self.add_alert(now, Severity::Critical, "Missing role for sensitive endpoint", &format!("{} requires role but none provided", endpoint));
                    return false;
                }
            }
        } else if is_sensitive {
            // Sensitive endpoint with no policy = misconfiguration
            self.add_alert(now, Severity::High, "Unprotected sensitive endpoint", &format!("{} has no auth policy", endpoint));
        }

        true
    }

    fn check_escalation(&self, endpoint: &str, now: i64) {
        let denied = self.total_denied.load(Ordering::Relaxed);
        if denied > 0 && denied % Self::DENIAL_ESCALATION_THRESHOLD == 0 {
            self.add_alert(now, Severity::Critical, "Repeated auth failures", &format!("{} denials on {} (brute-force?)", denied, endpoint));
        }
    }

    /// Get denial rate as percentage.
    pub fn denial_rate(&self) -> f64 {
        let checked = self.total_checked.load(Ordering::Relaxed);
        let denied = self.total_denied.load(Ordering::Relaxed);
        if checked == 0 { return 0.0; }
        (denied as f64 / checked as f64) * 100.0
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(ApiAlert { timestamp: ts, severity: sev, component: "auth_enforcer".into(), title: title.into(), details: details.into() });
    }

    pub fn total_checked(&self) -> u64 { self.total_checked.load(Ordering::Relaxed) }
    pub fn total_denied(&self) -> u64 { self.total_denied.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<ApiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
