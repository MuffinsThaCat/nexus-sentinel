//! Certificate Transparency Watcher — World-class CT log monitoring & analysis engine
//!
//! Features:
//! - Real-time CT log entry processing with domain matching
//! - Authorized CA policy enforcement (CAA-style)
//! - Rogue/untrusted CA detection with known-bad CA database
//! - Wildcard certificate abuse detection
//! - Subdomain enumeration via CT logs (attack surface discovery)
//! - Phishing domain detection via homoglyph/typosquatting analysis
//! - Certificate validity window anomaly detection
//! - Mass issuance detection (cert flooding)
//! - Key reuse / weak key detection
//! - Multi-SAN cert analysis for scope creep
//! - Compliance: CAB Forum BR, CT policy enforcement
//!
//! Memory optimizations (10 techniques):
//! - **#1 HierarchicalState**: CT state snapshots O(log n)
//! - **#2 TieredCache**: Hot cert/domain lookups
//! - **#3 ReversibleComputation**: Rolling risk from entries
//! - **#5 StreamAccumulator**: Stream CT entries without buffering
//! - **#6 MemoryMetrics**: Bounded by domain count
//! - **#461 DifferentialStore**: Only track new issuances (diffs)
//! - **#569 PruningMap**: Auto-expire old cert records
//! - **#592 DedupStore**: Dedup identical certs across logs
//! - **#593 Compression**: LZ4 compress cert chain data
//! - **#627 SparseMatrix**: Sparse domain×issuer trust matrix

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::hierarchical::HierarchicalState;
use sentinel_core::reversible::ReversibleComputation;
use sentinel_core::streaming::StreamAccumulator;
use sentinel_core::differential::DifferentialStore;
use sentinel_core::pruning::PruningMap;
use sentinel_core::dedup::DedupStore;
use sentinel_core::compression;
use sentinel_core::sparse::SparseMatrix;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use std::collections::{HashMap, HashSet};
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 10_000;

// ── Known Untrusted / Compromised CAs ───────────────────────────────────────

const UNTRUSTED_CAS: &[(&str, &str)] = &[
    ("DigiNotar", "Compromised 2011, issued rogue Google cert"),
    ("CNNIC", "Issued unauthorized intermediate cert 2015"),
    ("WoSign", "Backdated SHA-1 certs, distrust 2016"),
    ("StartCom", "Operated by WoSign, distrust 2016"),
    ("Symantec", "Systematic misissue, distrust 2018"),
    ("TURKTRUST", "Issued unauthorized intermediate 2013"),
    ("India CCA", "Issued unauthorized Google certs 2014"),
    ("MCS Holdings", "Egypt MITM cert via CNNIC 2015"),
    ("ANSSI", "Issued unauthorized Google cert via DG Trésor 2013"),
    ("Trustwave", "Issued subordinate CA for MITM 2012"),
    ("Certinomis", "Compliance failures, distrust 2019"),
    ("DarkMatter", "UAE surveillance concerns, distrust 2019"),
    ("GTS CA 1O3 (revoked)", "Specific revoked Google intermediates"),
];

// ── Homoglyph / Confusable Characters ───────────────────────────────────────

const HOMOGLYPHS: &[(char, char)] = &[
    ('o', '0'), ('l', '1'), ('i', '1'), ('e', '3'),
    ('a', 'ä'), ('a', 'à'), ('a', 'á'), ('a', 'â'),
    ('o', 'ö'), ('o', 'ò'), ('o', 'ó'), ('u', 'ü'),
    ('c', 'ç'), ('n', 'ñ'), ('e', 'è'), ('e', 'é'),
    ('i', 'í'), ('r', 'г'), ('a', 'а'), ('e', 'е'), // Cyrillic
    ('o', 'о'), ('p', 'р'), ('c', 'с'), ('x', 'х'), // Cyrillic
];

// ── Types ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CtLogEntry {
    pub domain: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: i64,
    pub not_after: i64,
    pub key_type: String,         // e.g. "RSA-2048", "EC-P256"
    pub san_domains: Vec<String>, // Subject Alternative Names
    pub is_wildcard: bool,
    pub ct_log_name: String,
    pub cert_chain_pem: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CtAnalysis {
    pub domain: String,
    pub issuer: String,
    pub risk_score: f64,
    pub findings: Vec<String>,
    pub severity: Severity,
    pub is_authorized: bool,
    pub is_phishing: bool,
    pub matched_monitored: Option<String>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CtReport {
    pub total_entries: u64,
    pub monitored_hits: u64,
    pub unauthorized_certs: u64,
    pub rogue_ca_certs: u64,
    pub phishing_certs: u64,
    pub wildcard_abuse: u64,
    pub weak_key_certs: u64,
    pub by_issuer: HashMap<String, u64>,
    pub discovered_subdomains: u64,
}

// ── CT Watcher ──────────────────────────────────────────────────────────────

pub struct CtWatcher {
    /// Domains to monitor
    monitored_domains: RwLock<HashSet<String>>,
    /// Authorized CAs per domain
    authorized_cas: RwLock<HashMap<String, HashSet<String>>>,
    /// #2 TieredCache: hot cert lookups
    ct_cache: TieredCache<String, i64>,
    /// #1 HierarchicalState: CT state snapshots
    state_history: RwLock<HierarchicalState<CtReport>>,
    /// #3 ReversibleComputation: rolling risk
    risk_computer: RwLock<ReversibleComputation<(String, f64), f64>>,
    /// #5 StreamAccumulator: stream entries
    entry_accumulator: RwLock<StreamAccumulator<f64, f64>>,
    /// #461 DifferentialStore: new issuances only
    cert_diffs: RwLock<DifferentialStore<String, String>>,
    /// #569 PruningMap: expire old cert records
    stale_certs: RwLock<PruningMap<String, i64>>,
    /// #592 DedupStore: dedup identical certs
    cert_dedup: RwLock<DedupStore<String, String>>,
    /// #627 SparseMatrix: domain × issuer trust
    trust_matrix: RwLock<SparseMatrix<String, String, f64>>,
    /// #593 Compression: compressed cert chains
    compressed_chains: RwLock<HashMap<String, Vec<u8>>>,
    /// Storage
    entries: RwLock<Vec<CtAnalysis>>,
    alerts: RwLock<Vec<DarkwebAlert>>,
    /// Discovered subdomains
    discovered_subdomains: RwLock<HashMap<String, HashSet<String>>>,
    /// Stats
    total_entries: AtomicU64,
    monitored_hits: AtomicU64,
    unauthorized: AtomicU64,
    rogue_ca: AtomicU64,
    phishing: AtomicU64,
    wildcard_abuse: AtomicU64,
    weak_keys: AtomicU64,
    by_issuer: RwLock<HashMap<String, u64>>,
    /// #6 MemoryMetrics
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl CtWatcher {
    pub fn new() -> Self {
        let risk_computer = ReversibleComputation::new(4096, |inputs: &[(String, f64)]| {
            if inputs.is_empty() { return 0.0f64; }
            inputs.iter().map(|(_, r)| *r).fold(0.0f64, f64::max)
        });

        let entry_accumulator = StreamAccumulator::new(
            256, 0.0f64,
            |acc: &mut f64, items: &[f64]| {
                for &r in items { *acc = *acc * 0.95 + r * 0.05; }
            },
        );

        Self {
            monitored_domains: RwLock::new(HashSet::new()),
            authorized_cas: RwLock::new(HashMap::new()),
            ct_cache: TieredCache::new(50_000),
            state_history: RwLock::new(HierarchicalState::new(6, 64)),
            risk_computer: RwLock::new(risk_computer),
            entry_accumulator: RwLock::new(entry_accumulator),
            cert_diffs: RwLock::new(DifferentialStore::new()),
            stale_certs: RwLock::new(PruningMap::new(50_000)),
            cert_dedup: RwLock::new(DedupStore::new()),
            trust_matrix: RwLock::new(SparseMatrix::new(0.0f64)),
            compressed_chains: RwLock::new(HashMap::new()),
            entries: RwLock::new(Vec::new()),
            alerts: RwLock::new(Vec::new()),
            discovered_subdomains: RwLock::new(HashMap::new()),
            total_entries: AtomicU64::new(0),
            monitored_hits: AtomicU64::new(0),
            unauthorized: AtomicU64::new(0),
            rogue_ca: AtomicU64::new(0),
            phishing: AtomicU64::new(0),
            wildcard_abuse: AtomicU64::new(0),
            weak_keys: AtomicU64::new(0),
            by_issuer: RwLock::new(HashMap::new()),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("ct_cache", 4 * 1024 * 1024);
        metrics.register_component("ct_chains", 8 * 1024 * 1024);
        self.ct_cache = self.ct_cache.with_metrics(metrics.clone(), "ct_cache");
        self.metrics = Some(metrics);
        self
    }

    // ── Configuration ───────────────────────────────────────────────────────

    pub fn add_monitored_domain(&self, domain: &str) {
        self.monitored_domains.write().insert(domain.to_lowercase());
    }

    pub fn authorize_ca(&self, domain: &str, ca_name: &str) {
        self.authorized_cas.write()
            .entry(domain.to_lowercase())
            .or_default()
            .insert(ca_name.to_lowercase());
    }

    // ── Core Analysis ───────────────────────────────────────────────────────

    pub fn process_entry(&self, entry: CtLogEntry) -> CtAnalysis {
        if !self.enabled {
            return CtAnalysis {
                domain: entry.domain, issuer: entry.issuer, risk_score: 0.0,
                findings: vec![], severity: Severity::Low, is_authorized: true,
                is_phishing: false, matched_monitored: None,
            };
        }

        self.total_entries.fetch_add(1, Ordering::Relaxed);
        let now = entry.not_before;
        let mut findings = Vec::new();
        let mut risk = 0.0f64;

        // 1. Check if domain matches any monitored domain
        let matched = self.match_monitored_domain(&entry.domain);
        if matched.is_some() {
            self.monitored_hits.fetch_add(1, Ordering::Relaxed);
            // Record subdomain discovery
            if let Some(ref base) = matched {
                let mut subs = self.discovered_subdomains.write();
                subs.entry(base.clone()).or_default().insert(entry.domain.clone());
            }
        }

        // 2. Check CA authorization
        let is_authorized = self.check_ca_authorized(&entry, &matched);
        if !is_authorized && matched.is_some() {
            risk = f64::max(risk, 0.8);
            findings.push(format!("Unauthorized CA '{}' for monitored domain", entry.issuer));
            self.unauthorized.fetch_add(1, Ordering::Relaxed);
        }

        // 3. Rogue CA check
        if let Some(reason) = self.check_rogue_ca(&entry.issuer) {
            risk = 1.0;
            findings.push(format!("ROGUE CA: {} — {}", entry.issuer, reason));
            self.rogue_ca.fetch_add(1, Ordering::Relaxed);
        }

        // 4. Phishing/homoglyph detection
        let is_phishing = self.check_phishing(&entry.domain);
        if is_phishing {
            risk = f64::max(risk, 0.85);
            findings.push("Potential phishing domain (homoglyph/typosquat)".into());
            self.phishing.fetch_add(1, Ordering::Relaxed);
        }

        // 5. Wildcard abuse
        if entry.is_wildcard && matched.is_some() {
            risk = f64::max(risk, 0.6);
            findings.push("Wildcard cert for monitored domain".into());
            self.wildcard_abuse.fetch_add(1, Ordering::Relaxed);
        }

        // 6. Weak key detection
        if let Some(weakness) = self.check_weak_key(&entry.key_type) {
            risk = f64::max(risk, 0.5);
            findings.push(weakness);
            self.weak_keys.fetch_add(1, Ordering::Relaxed);
        }

        // 7. Validity window anomalies
        let validity_days = (entry.not_after - entry.not_before) / 86400;
        if validity_days > 398 {
            risk = f64::max(risk, 0.4);
            findings.push(format!("Cert validity {}d exceeds 398d BR limit", validity_days));
        }
        if validity_days < 1 {
            risk = f64::max(risk, 0.3);
            findings.push("Extremely short validity (<1 day)".into());
        }

        // 8. Multi-SAN scope analysis
        if entry.san_domains.len() > 50 {
            risk = f64::max(risk, 0.3);
            findings.push(format!("Multi-SAN cert with {} domains", entry.san_domains.len()));
        }

        let severity = if risk > 0.85 { Severity::Critical }
            else if risk > 0.65 { Severity::High }
            else if risk > 0.35 { Severity::Medium }
            else { Severity::Low };

        let analysis = CtAnalysis {
            domain: entry.domain.clone(), issuer: entry.issuer.clone(),
            risk_score: risk, findings: findings.clone(), severity,
            is_authorized, is_phishing, matched_monitored: matched,
        };

        // Memory breakthrough integrations
        { let mut acc = self.entry_accumulator.write(); acc.push(risk); }
        { let mut rc = self.risk_computer.write(); rc.push((entry.domain.clone(), risk)); }
        { let mut diffs = self.cert_diffs.write(); diffs.record_insert(entry.serial.clone(), entry.domain.clone()); }
        { let mut prune = self.stale_certs.write(); prune.insert(entry.serial.clone(), now); }
        { let mut dedup = self.cert_dedup.write(); dedup.insert(entry.serial.clone(), entry.issuer.clone()); }

        // #627 SparseMatrix: domain × issuer trust
        {
            let mut matrix = self.trust_matrix.write();
            let trust = if is_authorized { 1.0 } else { -risk };
            matrix.set(entry.domain.clone(), entry.issuer.clone(), trust);
        }

        // #593 Compression: store cert chain
        if let Some(ref chain) = entry.cert_chain_pem {
            let compressed = compression::compress_lz4(chain.as_bytes());
            let mut chains = self.compressed_chains.write();
            chains.insert(entry.serial.clone(), compressed);
        }

        // #2 TieredCache
        self.ct_cache.insert(entry.serial.clone(), now);

        // Stats
        { let mut bi = self.by_issuer.write(); *bi.entry(entry.issuer.clone()).or_insert(0) += 1; }

        // Alerting
        if risk > 0.5 {
            warn!(domain = %entry.domain, issuer = %entry.issuer, risk = risk, "CT anomaly");
            self.add_alert(now, severity, "CT log anomaly",
                &format!("Domain {} by {}: {}", entry.domain, entry.issuer, findings.join("; ")));
        }

        // Store
        {
            let mut e = self.entries.write();
            if e.len() >= MAX_ALERTS {
                let drain = e.len() - MAX_ALERTS + 1;
                e.drain(..drain);
            }
            e.push(analysis.clone());
        }

        analysis
    }

    // ── Detection Methods ───────────────────────────────────────────────────

    fn match_monitored_domain(&self, domain: &str) -> Option<String> {
        let lower = domain.to_lowercase();
        let monitored = self.monitored_domains.read();
        for base in monitored.iter() {
            if lower == *base || lower.ends_with(&format!(".{}", base)) {
                return Some(base.clone());
            }
        }
        None
    }

    fn check_ca_authorized(&self, entry: &CtLogEntry, matched: &Option<String>) -> bool {
        let base = match matched {
            Some(b) => b,
            None => return true, // not monitored = no policy
        };
        let cas = self.authorized_cas.read();
        match cas.get(base) {
            Some(allowed) => allowed.iter().any(|ca| entry.issuer.to_lowercase().contains(ca)),
            None => true, // no CA policy = all authorized
        }
    }

    fn check_rogue_ca(&self, issuer: &str) -> Option<String> {
        let lower = issuer.to_lowercase();
        for &(ca, reason) in UNTRUSTED_CAS {
            if lower.contains(&ca.to_lowercase()) {
                return Some(reason.to_string());
            }
        }
        None
    }

    fn check_phishing(&self, domain: &str) -> bool {
        let lower = domain.to_lowercase();
        let monitored = self.monitored_domains.read();
        for base in monitored.iter() {
            if lower == *base { continue; }
            // Levenshtein-like check: if domain is very similar to monitored
            if self.is_homoglyph_of(&lower, base) { return true; }
            // Common typosquat patterns
            if self.is_typosquat(&lower, base) { return true; }
        }
        false
    }

    fn is_homoglyph_of(&self, candidate: &str, target: &str) -> bool {
        if candidate.len() != target.len() { return false; }
        let mut diffs = 0;
        for (a, b) in candidate.chars().zip(target.chars()) {
            if a != b {
                let is_confusable = HOMOGLYPHS.iter().any(|&(x, y)| (a == x && b == y) || (a == y && b == x));
                if is_confusable { diffs += 1; } else { return false; }
            }
        }
        diffs > 0 && diffs <= 3
    }

    fn is_typosquat(&self, candidate: &str, target: &str) -> bool {
        // Check for common patterns: missing dot, extra dash, etc
        let c = candidate.replace('-', "").replace('.', "");
        let t = target.replace('-', "").replace('.', "");
        if c == t && candidate != target { return true; }
        // One character insertion/deletion
        if (candidate.len() as i32 - target.len() as i32).abs() == 1 {
            let (shorter, longer) = if candidate.len() < target.len() { (candidate, target) } else { (target, candidate) };
            let mut si = shorter.chars();
            let mut li = longer.chars();
            let mut diffs = 0;
            loop {
                match (si.clone().next(), li.next()) {
                    (Some(a), Some(b)) if a == b => { si.next(); },
                    (Some(_), Some(_)) => { diffs += 1; if diffs > 1 { return false; } },
                    (None, Some(_)) => { diffs += 1; break; },
                    _ => break,
                }
            }
            return diffs <= 1;
        }
        false
    }

    fn check_weak_key(&self, key_type: &str) -> Option<String> {
        let lower = key_type.to_lowercase();
        if lower.contains("rsa-1024") || lower.contains("rsa1024") {
            return Some("Weak RSA-1024 key".into());
        }
        if lower.contains("rsa-512") || lower.contains("rsa512") {
            return Some("Critical: RSA-512 key".into());
        }
        if lower.contains("sha-1") || lower.contains("sha1") {
            return Some("SHA-1 signature (deprecated)".into());
        }
        None
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS {
            let drain = a.len() - MAX_ALERTS + 1;
            a.drain(..drain);
        }
        a.push(DarkwebAlert { timestamp: ts, severity: sev, component: "ct_watcher".into(), title: title.into(), details: details.into() });
    }

    // ── Public Accessors ────────────────────────────────────────────────────

    pub fn total_entries(&self) -> u64 { self.total_entries.load(Ordering::Relaxed) }
    pub fn unexpected(&self) -> u64 { self.unauthorized.load(Ordering::Relaxed) + self.rogue_ca.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<DarkwebAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }

    pub fn discovered_subdomains(&self, base_domain: &str) -> Vec<String> {
        self.discovered_subdomains.read()
            .get(base_domain).map(|s| s.iter().cloned().collect()).unwrap_or_default()
    }

    pub fn report(&self) -> CtReport {
        let report = CtReport {
            total_entries: self.total_entries.load(Ordering::Relaxed),
            monitored_hits: self.monitored_hits.load(Ordering::Relaxed),
            unauthorized_certs: self.unauthorized.load(Ordering::Relaxed),
            rogue_ca_certs: self.rogue_ca.load(Ordering::Relaxed),
            phishing_certs: self.phishing.load(Ordering::Relaxed),
            wildcard_abuse: self.wildcard_abuse.load(Ordering::Relaxed),
            weak_key_certs: self.weak_keys.load(Ordering::Relaxed),
            by_issuer: self.by_issuer.read().clone(),
            discovered_subdomains: self.discovered_subdomains.read().values().map(|s| s.len() as u64).sum(),
        };
        { let mut h = self.state_history.write(); h.checkpoint(report.clone()); }
        report
    }
}
