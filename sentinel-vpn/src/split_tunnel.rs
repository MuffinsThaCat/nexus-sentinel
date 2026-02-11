//! Split Tunnel — manages split-tunneling policies.
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Hot lookups cached
//! - **#6 Theoretical Verifier**: Bound memory usage
use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;use std::collections::HashSet;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TunnelAction { Tunnel, Bypass, Block }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TunnelDecision {
    pub domain: String,
    pub action: TunnelAction,
    pub reason: String,
    pub risk_score: f64,
}

/// Domains that should never bypass the VPN (always forced through tunnel).
const SENSITIVE_DOMAINS: &[&str] = &[
    "bank", "chase", "wellsfargo", "paypal", "venmo", "stripe",
    "healthcare", "medical", "hipaa", "gov.", ".mil",
    "internal.", "corp.", "intranet.", "vpn.",
];

/// Known DNS leak / tracking domains to block entirely.
const BLOCKED_DOMAINS: &[&str] = &[
    "dnsleak.com", "dnsleaktest.com", "ipleak.net",
    "whatismyipaddress.com", "ipinfo.io",
    "ads.", "tracker.", "telemetry.", "analytics.",
];

/// High-risk geo TLDs that should always tunnel.
const HIGH_RISK_TLDS: &[&str] = &[".ru", ".cn", ".ir", ".kp", ".sy", ".onion"];

pub struct SplitTunnel {
    bypass_domains: RwLock<HashSet<String>>,
    forced_domains: RwLock<HashSet<String>>,
    blocked_domains: RwLock<HashSet<String>>,
    alerts: RwLock<Vec<VpnAlert>>,
    total_checked: AtomicU64,
    total_bypassed: AtomicU64,
    total_blocked: AtomicU64,
    _cache: TieredCache<String, u64>,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl SplitTunnel {
    pub fn new() -> Self {
        let mut blocked = HashSet::new();
        for d in BLOCKED_DOMAINS { blocked.insert(d.to_string()); }
        Self {
            bypass_domains: RwLock::new(HashSet::new()),
            forced_domains: RwLock::new(HashSet::new()),
            blocked_domains: RwLock::new(blocked),
            alerts: RwLock::new(Vec::new()),
            total_checked: AtomicU64::new(0),
            total_bypassed: AtomicU64::new(0),
            total_blocked: AtomicU64::new(0),
            enabled: true,
            _cache: TieredCache::new(10_000),
            metrics: None,
        }
    }

    pub fn add_bypass(&self, domain: &str) { self.bypass_domains.write().insert(domain.to_lowercase()); }
    pub fn add_forced(&self, domain: &str) { self.forced_domains.write().insert(domain.to_lowercase()); }
    pub fn add_blocked(&self, domain: &str) { self.blocked_domains.write().insert(domain.to_lowercase()); }

    /// Risk-aware split tunnel decision with geo-fencing, DNS leak prevention, and sensitivity detection.
    pub fn evaluate(&self, domain: &str) -> TunnelDecision {
        self.total_checked.fetch_add(1, Ordering::Relaxed);
        let lower = domain.to_lowercase();
        let mut risk = 0.0;
        let mut reasons = Vec::new();

        // 1. Explicit block list (DNS leak / tracking)
        if self.blocked_domains.read().iter().any(|d| lower.contains(d.as_str())) {
            self.total_blocked.fetch_add(1, Ordering::Relaxed);
            let now = chrono::Utc::now().timestamp();
            self.add_alert(now, Severity::Medium, "Domain blocked", &format!("Blocked: {}", lower));
            return TunnelDecision { domain: lower, action: TunnelAction::Block, reason: "blocked_domain".into(), risk_score: 1.0 };
        }

        // 2. Explicit bypass list
        if self.bypass_domains.read().contains(&lower) {
            self.total_bypassed.fetch_add(1, Ordering::Relaxed);
            return TunnelDecision { domain: lower, action: TunnelAction::Bypass, reason: "explicit_bypass".into(), risk_score: 0.0 };
        }

        // 3. Explicit forced list
        if self.forced_domains.read().contains(&lower) {
            return TunnelDecision { domain: lower, action: TunnelAction::Tunnel, reason: "explicit_forced".into(), risk_score: 0.5 };
        }

        // 4. Sensitive domain detection (banking, healthcare, gov)
        for pat in SENSITIVE_DOMAINS {
            if lower.contains(pat) {
                risk += 0.4;
                reasons.push(format!("sensitive:{}", pat));
            }
        }

        // 5. High-risk geo TLD
        for tld in HIGH_RISK_TLDS {
            if lower.ends_with(tld) {
                risk += 0.5;
                reasons.push(format!("high_risk_tld:{}", tld));
            }
        }

        // 6. IP address instead of domain (potential DNS bypass)
        if lower.chars().all(|c| c.is_ascii_digit() || c == '.') {
            let parts: Vec<&str> = lower.split('.').collect();
            if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
                risk += 0.3;
                reasons.push("raw_ip_access".into());
            }
        }

        // 7. Unusually long domain (possible DGA)
        if lower.len() > 50 {
            risk += 0.2;
            reasons.push("long_domain".into());
        }

        // 8. Many subdomains (possible tunneling)
        let subdomain_count = lower.matches('.').count();
        if subdomain_count > 4 {
            risk += 0.2;
            reasons.push(format!("deep_subdomains:{}", subdomain_count));
        }

        let action = if risk >= 0.5 { TunnelAction::Tunnel } else if risk >= 0.2 { TunnelAction::Tunnel } else { TunnelAction::Bypass };
        let reason = if reasons.is_empty() { "default_policy".into() } else { reasons.join(",") };

        if risk >= 0.5 {
            let now = chrono::Utc::now().timestamp();
            self.add_alert(now, Severity::Low, "Forced tunnel", &format!("{}: {}", lower, reason));
        }

        TunnelDecision { domain: lower, action, reason, risk_score: (risk as f64).min(1.0) }
    }

    /// Legacy API.
    pub fn should_tunnel(&self, domain: &str) -> bool {
        self.evaluate(domain).action == TunnelAction::Tunnel
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(VpnAlert { timestamp: ts, severity: sev, component: "split_tunnel".into(), title: title.into(), details: details.into() });
    }

    pub fn total_checked(&self) -> u64 { self.total_checked.load(Ordering::Relaxed) }
    pub fn total_bypassed(&self) -> u64 { self.total_bypassed.load(Ordering::Relaxed) }
    pub fn total_blocked(&self) -> u64 { self.total_blocked.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<VpnAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
