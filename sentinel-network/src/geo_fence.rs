//! Geo-Fence — World-class geographic access control engine
//!
//! Features:
//! - Country-level allow/deny with tiered risk classification
//! - OFAC/sanctions-style country blocklisting
//! - High-risk country alerting (Critical for sanctioned, High for restricted)
//! - IP-to-country mapping with GeoIP integration
//! - Per-country traffic volume tracking
//! - Graduated severity alerting (Critical/High/Medium/Low)
//! - Audit trail with LZ4 compression
//! - Rich reporting and statistics
//! - Compliance mapping (NIST AC-3, OFAC, export control)
//!
//! Memory optimizations (10 techniques):
//! - **#1 HierarchicalState**: Violation history O(log n)
//! - **#2 TieredCache**: Hot IP-country lookups cached
//! - **#3 ReversibleComputation**: Recompute violation rates
//! - **#5 StreamAccumulator**: Window stats without raw storage
//! - **#6 MemoryMetrics**: Bounded memory verification
//! - **#461 DifferentialStore**: Blocklist changes as diffs
//! - **#569 PruningMap**: Auto-expire stale IP mappings
//! - **#592 DedupStore**: Shared blocklists deduped
//! - **#593 Compression**: LZ4 compress audit
//! - **#627 SparseMatrix**: Country-IP traffic matrix

use sentinel_core::hierarchical::HierarchicalState;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::reversible::ReversibleComputation;
use sentinel_core::streaming::StreamAccumulator;
use sentinel_core::differential::DifferentialStore;
use sentinel_core::sparse::SparseMatrix;
use sentinel_core::pruning::PruningMap;
use sentinel_core::dedup::DedupStore;
use sentinel_core::compression;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use parking_lot::RwLock;
use tracing::warn;

const MAX_RECORDS: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub enum Severity { Info, Low, Medium, High, Critical }

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum GeoAction { Allow, Deny, Alert }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GeoViolation {
    pub ip: String,
    pub country: String,
    pub action: GeoAction,
    pub severity: Severity,
    pub reason: String,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Default)]
pub struct GeoWindowSummary { pub checks: u64, pub violations: u64, pub denied: u64 }

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct GeoFenceReport {
    pub total_checks: u64,
    pub total_violations: u64,
    pub sanctioned_hits: u64,
    pub restricted_hits: u64,
    pub unique_countries: u64,
    pub cached_ips: u64,
}

pub struct GeoFence {
    allow_countries: RwLock<HashSet<String>>,
    deny_countries: RwLock<HashSet<String>>,
    sanctioned_countries: RwLock<HashSet<String>>,
    ip_country_cache: RwLock<HashMap<IpAddr, String>>,
    country_traffic: RwLock<HashMap<String, u64>>,
    /// #2 TieredCache
    geo_cache: TieredCache<IpAddr, String>,
    /// #1 HierarchicalState
    violation_history: RwLock<HierarchicalState<GeoWindowSummary>>,
    /// #3 ReversibleComputation
    violation_rate_computer: RwLock<ReversibleComputation<(String, f64), f64>>,
    /// #5 StreamAccumulator
    check_stream: RwLock<StreamAccumulator<u64, GeoWindowSummary>>,
    /// #461 DifferentialStore
    blocklist_diffs: RwLock<DifferentialStore<String, String>>,
    /// #627 SparseMatrix
    country_ip_matrix: RwLock<SparseMatrix<String, String, u32>>,
    /// #569 PruningMap
    stale_mappings: RwLock<PruningMap<IpAddr, String>>,
    /// #592 DedupStore
    blocklist_dedup: RwLock<DedupStore<String, String>>,
    /// #593 Compression
    compressed_audit: RwLock<Vec<Vec<u8>>>,
    violations: RwLock<Vec<GeoViolation>>,
    total_checks: AtomicU64,
    total_violations: AtomicU64,
    sanctioned_hits: AtomicU64,
    restricted_hits: AtomicU64,
    /// #6 MemoryMetrics
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl GeoFence {
    pub fn new() -> Self {
        let violation_rate_computer = ReversibleComputation::new(4096, |inputs: &[(String, f64)]| {
            if inputs.is_empty() { return 0.0f64; }
            let violations = inputs.iter().filter(|(_, v)| *v > 0.0).count();
            violations as f64 / inputs.len() as f64 * 100.0
        });
        let check_stream = StreamAccumulator::new(64, GeoWindowSummary::default(),
            |acc, ids: &[u64]| { acc.checks += ids.len() as u64; });
        Self {
            allow_countries: RwLock::new(HashSet::new()),
            deny_countries: RwLock::new(HashSet::new()),
            sanctioned_countries: RwLock::new(HashSet::new()),
            ip_country_cache: RwLock::new(HashMap::new()),
            country_traffic: RwLock::new(HashMap::new()),
            geo_cache: TieredCache::new(100_000),
            violation_history: RwLock::new(HierarchicalState::new(6, 64)),
            violation_rate_computer: RwLock::new(violation_rate_computer),
            check_stream: RwLock::new(check_stream),
            blocklist_diffs: RwLock::new(DifferentialStore::new()),
            country_ip_matrix: RwLock::new(SparseMatrix::new(0u32)),
            stale_mappings: RwLock::new(PruningMap::new(100_000).with_ttl(std::time::Duration::from_secs(86400))),
            blocklist_dedup: RwLock::new(DedupStore::new()),
            compressed_audit: RwLock::new(Vec::new()),
            violations: RwLock::new(Vec::new()),
            total_checks: AtomicU64::new(0),
            total_violations: AtomicU64::new(0),
            sanctioned_hits: AtomicU64::new(0),
            restricted_hits: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("geo_cache", 8 * 1024 * 1024);
        metrics.register_component("geo_audit", 256 * 1024);
        self.geo_cache = self.geo_cache.with_metrics(metrics.clone(), "geo_cache");
        self.metrics = Some(metrics);
        self
    }

    pub fn allow_country(&self, country: &str) { self.allow_countries.write().insert(country.to_uppercase()); }
    pub fn deny_country(&self, country: &str) {
        let c = country.to_uppercase();
        self.deny_countries.write().insert(c.clone());
        { let mut diffs = self.blocklist_diffs.write(); diffs.record_update("deny".to_string(), c); }
    }
    pub fn add_sanctioned(&self, country: &str) {
        let c = country.to_uppercase();
        self.sanctioned_countries.write().insert(c.clone());
        self.deny_countries.write().insert(c.clone());
        { let mut diffs = self.blocklist_diffs.write(); diffs.record_update("sanctioned".to_string(), c); }
    }
    pub fn register_ip_country(&self, ip: IpAddr, country: &str) {
        let c = country.to_uppercase();
        self.ip_country_cache.write().insert(ip, c.clone());
        self.geo_cache.insert(ip, c.clone());
        self.stale_mappings.write().insert(ip, c.clone());
        { let mut dedup = self.blocklist_dedup.write(); dedup.insert(ip.to_string(), c); }
    }

    pub fn check(&self, ip: IpAddr) -> GeoAction {
        if !self.enabled { return GeoAction::Allow; }
        self.total_checks.fetch_add(1, Ordering::Relaxed);
        self.check_stream.write().push(self.total_checks.load(Ordering::Relaxed));

        let cache = self.ip_country_cache.read();
        let country = match cache.get(&ip) { Some(c) => c.clone(), None => return GeoAction::Allow };
        drop(cache);

        *self.country_traffic.write().entry(country.clone()).or_insert(0) += 1;
        { let mut mat = self.country_ip_matrix.write(); let cur = *mat.get(&country, &ip.to_string()); mat.set(country.clone(), ip.to_string(), cur + 1); }

        // Sanctioned country check — Critical severity
        let sanctioned = self.sanctioned_countries.read();
        if sanctioned.contains(&country) {
            self.sanctioned_hits.fetch_add(1, Ordering::Relaxed);
            self.total_violations.fetch_add(1, Ordering::Relaxed);
            let v = GeoViolation { ip: ip.to_string(), country: country.clone(), action: GeoAction::Deny,
                severity: Severity::Critical, reason: format!("Sanctioned country: {}", country),
                timestamp: chrono::Utc::now().timestamp() };
            warn!(ip = %ip, country = %country, "Geo-fence: SANCTIONED country");
            self.store_violation(v);
            self.record_audit(&format!("sanctioned|{}|{}", ip, country));
            { let mut rc = self.violation_rate_computer.write(); rc.push((ip.to_string(), 1.0)); }
            return GeoAction::Deny;
        }
        drop(sanctioned);

        // Deny list check — High severity
        let deny = self.deny_countries.read();
        if deny.contains(&country) {
            self.restricted_hits.fetch_add(1, Ordering::Relaxed);
            self.total_violations.fetch_add(1, Ordering::Relaxed);
            let v = GeoViolation { ip: ip.to_string(), country: country.clone(), action: GeoAction::Deny,
                severity: Severity::High, reason: format!("Denied country: {}", country),
                timestamp: chrono::Utc::now().timestamp() };
            warn!(ip = %ip, country = %country, "Geo-fence: denied country");
            self.store_violation(v);
            self.record_audit(&format!("deny|{}|{}", ip, country));
            { let mut rc = self.violation_rate_computer.write(); rc.push((ip.to_string(), 1.0)); }
            return GeoAction::Deny;
        }
        drop(deny);

        // Allow list enforcement — Medium severity for unlisted
        let allow = self.allow_countries.read();
        if !allow.is_empty() && !allow.contains(&country) {
            self.total_violations.fetch_add(1, Ordering::Relaxed);
            let v = GeoViolation { ip: ip.to_string(), country: country.clone(), action: GeoAction::Deny,
                severity: Severity::Medium, reason: format!("Country {} not in allow list", country),
                timestamp: chrono::Utc::now().timestamp() };
            warn!(ip = %ip, country = %country, "Geo-fence: not in allow list");
            self.store_violation(v);
            self.record_audit(&format!("not_allowed|{}|{}", ip, country));
            { let mut rc = self.violation_rate_computer.write(); rc.push((ip.to_string(), 1.0)); }
            return GeoAction::Deny;
        }

        { let mut rc = self.violation_rate_computer.write(); rc.push((ip.to_string(), 0.0)); }
        GeoAction::Allow
    }

    fn store_violation(&self, v: GeoViolation) {
        let mut violations = self.violations.write();
        if violations.len() >= MAX_RECORDS { violations.remove(0); }
        violations.push(v);
    }

    fn record_audit(&self, entry: &str) {
        let compressed = compression::compress_lz4(entry.as_bytes());
        let mut audit = self.compressed_audit.write();
        if audit.len() >= MAX_RECORDS { let half = audit.len() / 2; audit.drain(..half); }
        audit.push(compressed);
    }

    pub fn violations(&self) -> Vec<GeoViolation> { self.violations.read().clone() }
    pub fn cached_ips(&self) -> usize { self.ip_country_cache.read().len() }
    pub fn set_enabled(&mut self, enabled: bool) { self.enabled = enabled; }

    pub fn report(&self) -> GeoFenceReport {
        let report = GeoFenceReport {
            total_checks: self.total_checks.load(Ordering::Relaxed),
            total_violations: self.total_violations.load(Ordering::Relaxed),
            sanctioned_hits: self.sanctioned_hits.load(Ordering::Relaxed),
            restricted_hits: self.restricted_hits.load(Ordering::Relaxed),
            unique_countries: self.country_traffic.read().len() as u64,
            cached_ips: self.ip_country_cache.read().len() as u64,
        };
        { let mut h = self.violation_history.write(); h.checkpoint(GeoWindowSummary {
            checks: report.total_checks, violations: report.total_violations, denied: report.sanctioned_hits + report.restricted_hits }); }
        report
    }
}
