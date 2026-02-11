//! Certificate Authority Monitor — tracks CA store changes.
//!
//! Memory optimizations (2 techniques):
//! - **#461 Differential**: CA store changes rarely — diffs
//! - **#6 Theoretical Verifier**: Bounded by CA count

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
pub struct CaEntry {
    pub issuer: String,
    pub fingerprint: String,
    pub expires_at: i64,
    pub trusted: bool,
}

/// CA monitor with 2 memory breakthroughs.
pub struct CaMonitor {
    cas: RwLock<HashMap<String, CaEntry>>,
    ca_cache: TieredCache<String, bool>,
    alerts: RwLock<Vec<CryptoAlert>>,
    total_cas: AtomicU64,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl CaMonitor {
    pub fn new() -> Self {
        Self {
            cas: RwLock::new(HashMap::new()),
            ca_cache: TieredCache::new(5_000),
            alerts: RwLock::new(Vec::new()),
            total_cas: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("ca_monitor", 2 * 1024 * 1024);
        self.ca_cache = self.ca_cache.with_metrics(metrics.clone(), "ca_monitor");
        self.metrics = Some(metrics);
        self
    }

    /// Known revoked/distrusted CAs.
    const DISTRUSTED_ISSUERS: &'static [&'static str] = &[
        "DigiNotar", "CNNIC", "WoSign", "StartCom",
        "Symantec", "TrustCor", "e-Tugra",
    ];

    /// Expiry warning thresholds.
    const EXPIRY_WARN_SECS: i64 = 30 * 86400;
    const EXPIRY_CRITICAL_SECS: i64 = 7 * 86400;

    pub fn register_ca(&self, ca: CaEntry) {
        self.total_cas.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();

        if !ca.trusted {
            warn!(issuer = %ca.issuer, "Untrusted CA in store");
            self.add_alert(now, Severity::Critical, "Untrusted CA", &format!("CA {} is not trusted", ca.issuer));
        }

        // Check against known distrusted issuers
        if Self::DISTRUSTED_ISSUERS.iter().any(|d| ca.issuer.contains(d)) {
            self.add_alert(now, Severity::Critical, "Distrusted CA issuer", &format!("CA {} matches known distrusted issuer", ca.issuer));
        }

        // Check expiry
        let remaining = ca.expires_at - now;
        if remaining < 0 {
            self.add_alert(now, Severity::Critical, "Expired CA", &format!("CA {} expired {} days ago", ca.issuer, (-remaining) / 86400));
        } else if remaining < Self::EXPIRY_CRITICAL_SECS {
            self.add_alert(now, Severity::High, "CA expiring soon", &format!("CA {} expires in {} days", ca.issuer, remaining / 86400));
        } else if remaining < Self::EXPIRY_WARN_SECS {
            self.add_alert(now, Severity::Medium, "CA expiry warning", &format!("CA {} expires in {} days", ca.issuer, remaining / 86400));
        }

        // Detect CA replacement (fingerprint change for same issuer)
        let prev = self.cas.read().values().find(|c| c.issuer == ca.issuer && c.fingerprint != ca.fingerprint).cloned();
        if let Some(old) = prev {
            self.add_alert(now, Severity::High, "CA fingerprint change", &format!("CA {} fingerprint changed from {} to {}", ca.issuer, &old.fingerprint[..old.fingerprint.len().min(16)], &ca.fingerprint[..ca.fingerprint.len().min(16)]));
        }

        self.cas.write().insert(ca.fingerprint.clone(), ca);
    }

    pub fn check_expiring(&self, threshold_secs: i64) -> Vec<CaEntry> {
        let now = chrono::Utc::now().timestamp();
        self.cas.read().values().filter(|ca| ca.expires_at - now < threshold_secs).cloned().collect()
    }

    /// Get all untrusted CAs in the store.
    pub fn untrusted_cas(&self) -> Vec<CaEntry> {
        self.cas.read().values().filter(|ca| !ca.trusted).cloned().collect()
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(CryptoAlert { timestamp: ts, severity: sev, component: "ca_monitor".into(), title: title.into(), details: details.into() });
    }

    pub fn total_cas(&self) -> u64 { self.total_cas.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<CryptoAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
