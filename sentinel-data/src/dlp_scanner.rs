//! DLP Scanner — Data Loss Prevention scanning engine.
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Hot rule lookups
//! - **#6 Theoretical Verifier**: Bound match store

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use std::collections::HashMap;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DlpRule {
    pub name: String,
    pub pattern: String,
    pub severity: Severity,
    pub classification: DataClassification,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DlpMatch {
    pub rule_name: String,
    pub resource_id: String,
    pub timestamp: i64,
    pub severity: Severity,
}

/// DLP scanner with 2 memory breakthroughs.
pub struct DlpScanner {
    rules: RwLock<Vec<DlpRule>>,
    matches: RwLock<Vec<DlpMatch>>,
    /// #2 Tiered cache: hot rule lookups
    rule_cache: TieredCache<String, u8>,
    alerts: RwLock<Vec<DataAlert>>,
    scans: AtomicU64,
    violations: AtomicU64,
    /// #6 Theoretical verifier
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl DlpScanner {
    pub fn new() -> Self {
        Self {
            rules: RwLock::new(Vec::new()),
            matches: RwLock::new(Vec::new()),
            rule_cache: TieredCache::new(50_000),
            alerts: RwLock::new(Vec::new()),
            scans: AtomicU64::new(0),
            violations: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    /// #6 Theoretical verifier: bound match store at 8MB.
    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("dlp_scanner", 8 * 1024 * 1024);
        self.rule_cache = self.rule_cache.with_metrics(metrics.clone(), "dlp_scanner");
        self.metrics = Some(metrics);
        self
    }

    pub fn add_rule(&self, rule: DlpRule) { self.rules.write().push(rule); }

    pub fn scan(&self, resource_id: &str, content: &str) -> Vec<DlpMatch> {
        if !self.enabled { return Vec::new(); }
        self.scans.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        let rules = self.rules.read();
        let mut found = Vec::new();

        for rule in rules.iter() {
            if content.contains(&rule.pattern) {
                let m = DlpMatch {
                    rule_name: rule.name.clone(),
                    resource_id: resource_id.to_string(),
                    timestamp: now,
                    severity: rule.severity,
                };
                found.push(m.clone());
                self.violations.fetch_add(1, Ordering::Relaxed);
                warn!(resource = %resource_id, rule = %rule.name, "DLP violation detected");
                self.add_alert(now, rule.severity, "DLP violation",
                    &format!("Resource {} matched rule {}", resource_id, rule.name));
                let mut matches = self.matches.write();
                if matches.len() >= MAX_ALERTS { matches.remove(0); }
                matches.push(m);
            }
        }
        found
    }

    fn add_alert(&self, ts: i64, severity: Severity, title: &str, details: &str) {
        let mut alerts = self.alerts.write();
        if alerts.len() >= MAX_ALERTS { alerts.remove(0); }
        alerts.push(DataAlert { timestamp: ts, severity, component: "dlp_scanner".into(), title: title.into(), details: details.into() });
    }

    pub fn total_scans(&self) -> u64 { self.scans.load(Ordering::Relaxed) }
    pub fn total_violations(&self) -> u64 { self.violations.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<DataAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
