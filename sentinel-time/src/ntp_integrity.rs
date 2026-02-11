//! NTP Integrity Monitor — validates NTP source integrity.
//!
//! Memory optimizations (2 techniques):
//! - **#461 Differential**: NTP sources change slowly
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
pub struct NtpSource {
    pub server: String,
    pub stratum: u8,
    pub authenticated: bool,
    pub trusted: bool,
    pub last_check: i64,
}

/// NTP integrity monitor.
pub struct NtpIntegrity {
    sources: RwLock<HashMap<String, NtpSource>>,
    source_cache: TieredCache<String, bool>,
    alerts: RwLock<Vec<TimeAlert>>,
    total_checked: AtomicU64,
    untrusted: AtomicU64,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl NtpIntegrity {
    pub fn new() -> Self {
        Self {
            sources: RwLock::new(HashMap::new()),
            source_cache: TieredCache::new(1_000),
            alerts: RwLock::new(Vec::new()),
            total_checked: AtomicU64::new(0),
            untrusted: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("ntp_integrity", 1024 * 1024);
        self.source_cache = self.source_cache.with_metrics(metrics.clone(), "ntp_integrity");
        self.metrics = Some(metrics);
        self
    }

    /// Maximum acceptable stratum level (higher = less accurate).
    const MAX_SAFE_STRATUM: u8 = 3;

    /// Stratum 16 means unsynchronized per NTP spec.
    const UNSYNC_STRATUM: u8 = 16;

    pub fn check_source(&self, source: NtpSource) {
        self.total_checked.fetch_add(1, Ordering::Relaxed);
        let now = source.last_check;

        // Unsynchronized source (stratum 16)
        if source.stratum >= Self::UNSYNC_STRATUM {
            self.untrusted.fetch_add(1, Ordering::Relaxed);
            warn!(server = %source.server, stratum = source.stratum, "Unsynchronized NTP source");
            self.add_alert(now, Severity::Critical, "Unsynchronized NTP", &format!("{} stratum {} (unsynchronized)", source.server, source.stratum));
        } else if !source.trusted || !source.authenticated {
            self.untrusted.fetch_add(1, Ordering::Relaxed);
            warn!(server = %source.server, stratum = source.stratum, authed = source.authenticated, "Untrusted NTP source");
            self.add_alert(now, Severity::High, "Untrusted NTP", &format!("{} stratum {} is not trusted/authenticated", source.server, source.stratum));
        } else if source.stratum > Self::MAX_SAFE_STRATUM {
            self.add_alert(now, Severity::Medium, "High stratum NTP", &format!("{} stratum {} (recommended ≤ {})", source.server, source.stratum, Self::MAX_SAFE_STRATUM));
        }

        // Detect source changes (possible NTP spoofing)
        let prev = self.sources.read().get(&source.server).cloned();
        if let Some(prev) = prev {
            if prev.stratum != source.stratum {
                self.add_alert(now, Severity::High, "NTP stratum change", &format!("{} stratum changed {} → {}", source.server, prev.stratum, source.stratum));
            }
            if prev.authenticated && !source.authenticated {
                self.add_alert(now, Severity::Critical, "NTP auth downgrade", &format!("{} lost authentication", source.server));
            }
        }

        self.sources.write().insert(source.server.clone(), source);
    }

    /// Get all trusted sources.
    pub fn trusted_sources(&self) -> Vec<NtpSource> {
        self.sources.read().values().filter(|s| s.trusted && s.authenticated).cloned().collect()
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(TimeAlert { timestamp: ts, severity: sev, component: "ntp_integrity".into(), title: title.into(), details: details.into() });
    }

    pub fn total_checked(&self) -> u64 { self.total_checked.load(Ordering::Relaxed) }
    pub fn untrusted(&self) -> u64 { self.untrusted.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<TimeAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
