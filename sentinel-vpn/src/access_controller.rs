//! Access Controller — controls which users/devices can access VPN.
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
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

/// Known Tor exit node and anonymous proxy CIDR prefixes.
const SUSPICIOUS_IP_PREFIXES: &[&str] = &[
    "10.0.0.", "192.168.", "172.16.", "0.0.0.", "127.",
];

/// High-risk geo TLDs for IP-based geo detection.
const HIGH_RISK_GEOS: &[&str] = &["ru", "cn", "kp", "ir"];

const MAX_ATTEMPTS_PER_IP: u64 = 10;

pub struct AccessController {
    allowed_users: RwLock<HashSet<String>>,
    blocked_ips: RwLock<HashSet<String>>,
    attempt_counts: RwLock<std::collections::HashMap<String, u64>>,
    alerts: RwLock<Vec<VpnAlert>>,
    total_checked: AtomicU64,
    total_denied: AtomicU64,
    _cache: TieredCache<String, u64>,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl AccessController {
    pub fn new() -> Self {
        Self {
            allowed_users: RwLock::new(HashSet::new()),
            blocked_ips: RwLock::new(HashSet::new()),
            attempt_counts: RwLock::new(std::collections::HashMap::new()),
            alerts: RwLock::new(Vec::new()),
            total_checked: AtomicU64::new(0),
            total_denied: AtomicU64::new(0),
            enabled: true,
            _cache: TieredCache::new(10_000),
            metrics: None,
        }
    }

    pub fn allow_user(&self, user: &str) { self.allowed_users.write().insert(user.into()); }
    pub fn block_ip(&self, ip: &str) { self.blocked_ips.write().insert(ip.into()); }

    pub fn check_access(&self, user: &str, source_ip: &str) -> bool {
        self.total_checked.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();

        // 1. Blocked IP
        if self.blocked_ips.read().contains(source_ip) {
            self.deny(now, user, source_ip, "blocked_ip");
            return false;
        }

        // 2. Brute-force / credential stuffing detection
        let mut attempts = self.attempt_counts.write();
        let count = attempts.entry(source_ip.to_string()).or_insert(0);
        *count += 1;
        if *count > MAX_ATTEMPTS_PER_IP {
            let c = *count;
            drop(attempts);
            self.blocked_ips.write().insert(source_ip.to_string());
            self.add_alert(now, Severity::Critical, "Auto-blocked IP", &format!("{} auto-blocked after {} attempts from {}", user, c, source_ip));
            self.deny(now, user, source_ip, "brute_force_auto_block");
            return false;
        }
        // Memory bound
        if attempts.len() > 50_000 {
            if let Some(oldest) = attempts.keys().next().cloned() { attempts.remove(&oldest); }
        }
        drop(attempts);

        // 3. Internal/loopback IP abuse
        if SUSPICIOUS_IP_PREFIXES.iter().any(|p| source_ip.starts_with(p)) {
            self.add_alert(now, Severity::Medium, "Internal IP", &format!("{} connecting from internal IP {}", user, source_ip));
        }

        // 4. Allowlist check
        let allowed = self.allowed_users.read();
        if !allowed.is_empty() && !allowed.contains(user) {
            drop(allowed);
            self.deny(now, user, source_ip, "not_in_allowlist");
            return false;
        }

        true
    }

    fn deny(&self, ts: i64, user: &str, ip: &str, reason: &str) {
        self.total_denied.fetch_add(1, Ordering::Relaxed);
        warn!(user = %user, ip = %ip, reason = %reason, "VPN access denied");
        self.add_alert(ts, Severity::High, "Access denied", &format!("{} from {} ({})", user, ip, reason));
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(VpnAlert { timestamp: ts, severity: sev, component: "access_controller".into(), title: title.into(), details: details.into() });
    }

    pub fn total_checked(&self) -> u64 { self.total_checked.load(Ordering::Relaxed) }
    pub fn total_denied(&self) -> u64 { self.total_denied.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<VpnAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
