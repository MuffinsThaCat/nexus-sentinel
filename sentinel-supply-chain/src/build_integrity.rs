//! Build Integrity — World-class CI/CD pipeline integrity & reproducibility engine
//!
//! Features:
//! - Reproducible build enforcement with known-good hash comparison
//! - Environment variable tampering detection (LD_PRELOAD, DYLD_INSERT, proxy injection)
//! - Commit message social engineering detection (vague/urgent patterns)
//! - Build timestamp anomaly detection (future dates, stale builds)
//! - Output hash strength validation (SHA-256+ required)
//! - Graduated severity alerting (Critical/High/Medium/Low)
//! - Audit trail with LZ4 compression
//! - Compliance mapping (NIST SP 800-218 SSDF, SLSA v1.0 Build L1-L4)
//!
//! Memory optimizations (10 techniques):
//! - **#1 HierarchicalState**: Build history O(log n)
//! - **#2 TieredCache**: Hot build lookups cached
//! - **#3 ReversibleComputation**: Recompute pass/fail rates
//! - **#5 StreamAccumulator**: Window stats without raw storage
//! - **#6 MemoryMetrics**: Bounded memory verification
//! - **#461 DifferentialStore**: Known-good hash diffs
//! - **#569 PruningMap**: Auto-expire old build records
//! - **#592 DedupStore**: Dedup build IDs
//! - **#593 Compression**: LZ4 compress audit
//! - **#627 SparseMatrix**: Project-to-finding matrix

use crate::types::*;
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
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;
const MAX_RECORDS: usize = 10_000;

#[derive(Debug, Clone, Default)]
pub struct BuildWindowSummary { pub builds: u64, pub failures: u64 }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BuildRecord {
    pub build_id: String,
    pub project: String,
    pub commit_hash: String,
    pub output_hash: String,
    pub reproducible: bool,
    pub built_at: i64,
}

const SUSPICIOUS_ENV_PATTERNS: &[&str] = &[
    "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "http_proxy=", "https_proxy=",
    "NODE_OPTIONS=--require", "PYTHONSTARTUP=", "RUBYOPT=-r",
    "PERL5OPT=", "GOFLAGS=-overlay", "RUSTFLAGS=--cfg",
];

const SUSPICIOUS_COMMIT_PATTERNS: &[&str] = &[
    "dependency update", "bump version", "fix typo", "minor fix",
    "hotfix", "urgent patch", "security fix",
];

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BuildVerdict {
    pub trusted: bool,
    pub findings: Vec<String>,
    pub severity: Severity,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct BuildIntegrityReport {
    pub total_builds: u64,
    pub total_failures: u64,
    pub pass_rate_pct: f64,
}

pub struct BuildIntegrity {
    builds: RwLock<Vec<BuildRecord>>,
    known_hashes: RwLock<std::collections::HashMap<String, String>>,
    alerts: RwLock<Vec<SupplyChainAlert>>,
    total_builds: AtomicU64,
    total_failures: AtomicU64,
    /// #2 TieredCache
    build_cache: TieredCache<String, u64>,
    /// #1 HierarchicalState
    history: RwLock<HierarchicalState<BuildWindowSummary>>,
    /// #3 ReversibleComputation
    pass_rate_computer: RwLock<ReversibleComputation<(String, f64), f64>>,
    /// #5 StreamAccumulator
    build_stream: RwLock<StreamAccumulator<u64, BuildWindowSummary>>,
    /// #461 DifferentialStore
    hash_diffs: RwLock<DifferentialStore<String, String>>,
    /// #627 SparseMatrix
    project_finding_matrix: RwLock<SparseMatrix<String, String, u32>>,
    /// #569 PruningMap
    stale_builds: RwLock<PruningMap<String, i64>>,
    /// #592 DedupStore
    build_dedup: RwLock<DedupStore<String, String>>,
    /// #593 Compression
    compressed_audit: RwLock<Vec<Vec<u8>>>,
    /// #6 MemoryMetrics
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl BuildIntegrity {
    pub fn new() -> Self {
        let pass_rate_computer = ReversibleComputation::new(4096, |inputs: &[(String, f64)]| {
            if inputs.is_empty() { return 0.0f64; }
            let passed = inputs.iter().filter(|(_, v)| *v == 0.0).count();
            passed as f64 / inputs.len() as f64 * 100.0
        });
        let build_stream = StreamAccumulator::new(64, BuildWindowSummary::default(),
            |acc, ids: &[u64]| { acc.builds += ids.len() as u64; });
        Self {
            builds: RwLock::new(Vec::new()),
            known_hashes: RwLock::new(std::collections::HashMap::new()),
            alerts: RwLock::new(Vec::new()),
            total_builds: AtomicU64::new(0),
            total_failures: AtomicU64::new(0),
            build_cache: TieredCache::new(10_000),
            history: RwLock::new(HierarchicalState::new(6, 64)),
            pass_rate_computer: RwLock::new(pass_rate_computer),
            build_stream: RwLock::new(build_stream),
            hash_diffs: RwLock::new(DifferentialStore::new()),
            project_finding_matrix: RwLock::new(SparseMatrix::new(0u32)),
            stale_builds: RwLock::new(PruningMap::new(50_000).with_ttl(std::time::Duration::from_secs(30 * 86400))),
            build_dedup: RwLock::new(DedupStore::new()),
            compressed_audit: RwLock::new(Vec::new()),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("bi_cache", 2 * 1024 * 1024);
        metrics.register_component("bi_audit", 128 * 1024);
        self.build_cache = self.build_cache.with_metrics(metrics.clone(), "bi_cache");
        self.metrics = Some(metrics);
        self
    }

    pub fn register_known_good(&self, project: &str, commit: &str, output_hash: &str) {
        let key = format!("{}:{}", project, commit);
        self.known_hashes.write().insert(key.clone(), output_hash.to_string());
        { let mut diffs = self.hash_diffs.write(); diffs.record_update(key, output_hash.to_string()); }
    }

    pub fn verify_build(&self, build: &BuildRecord, env_vars: &str, commit_msg: &str) -> BuildVerdict {
        let count = self.total_builds.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        self.build_stream.write().push(count);
        self.build_cache.insert(build.build_id.clone(), count);
        self.stale_builds.write().insert(build.build_id.clone(), now);
        { let mut dedup = self.build_dedup.write(); dedup.insert(build.build_id.clone(), build.output_hash.clone()); }

        let mut findings = Vec::new();
        let mut sev = Severity::Low;

        // 1. Reproducibility (SLSA Build L3 requires hermetic builds)
        if !build.reproducible {
            findings.push("MEDIUM: non_reproducible — fails SLSA Build L3 hermetic requirement".into());
            sev = Severity::Medium;
        }

        // 2. Hash consistency against known-good (SLSA Build L2 provenance)
        let key = format!("{}:{}", build.project, build.commit_hash);
        if let Some(known) = self.known_hashes.read().get(&key) {
            if *known != build.output_hash {
                findings.push(format!("CRITICAL: hash_mismatch — expected={} got={}", &known[..known.len().min(12)], &build.output_hash[..build.output_hash.len().min(12)]));
                sev = Severity::Critical;
            }
        }

        // 3. Environment tampering (NIST SP 800-218 PO.3.2)
        let env_lower = env_vars.to_lowercase();
        for pat in SUSPICIOUS_ENV_PATTERNS {
            if env_lower.contains(&pat.to_lowercase()) {
                findings.push(format!("HIGH: suspicious_env:{} — build environment compromised", pat));
                if sev < Severity::High { sev = Severity::High; }
            }
        }

        // 4. Commit message social engineering
        let msg_lower = commit_msg.to_lowercase();
        let mut suspicious_patterns = 0;
        for pat in SUSPICIOUS_COMMIT_PATTERNS {
            if msg_lower.contains(pat) { suspicious_patterns += 1; }
        }
        if suspicious_patterns >= 2 {
            findings.push(format!("MEDIUM: suspicious_commit_msg:matches={} — possible social engineering", suspicious_patterns));
            if sev < Severity::Medium { sev = Severity::Medium; }
        }

        // 5. Build timestamp anomaly
        let age_hours = (now - build.built_at).abs() / 3600;
        if build.built_at > now + 300 {
            findings.push("HIGH: future_timestamp — clock tampering or replay attack".into());
            if sev < Severity::High { sev = Severity::High; }
        } else if age_hours > 720 {
            findings.push(format!("LOW: stale_build:{}h — re-build recommended", age_hours));
        }

        // 6. Output hash strength
        if build.output_hash.is_empty() || build.output_hash.len() < 32 {
            findings.push("MEDIUM: weak_hash — SHA-256+ required for SLSA compliance".into());
            if sev < Severity::Medium { sev = Severity::Medium; }
        }

        // Record findings in sparse matrix
        for f in &findings {
            let cat = if f.starts_with("CRITICAL") { "Critical" } else if f.starts_with("HIGH") { "High" } else if f.starts_with("MEDIUM") { "Medium" } else { "Low" };
            let mut mat = self.project_finding_matrix.write();
            let cur = *mat.get(&build.project, &cat.to_string());
            mat.set(build.project.clone(), cat.to_string(), cur + 1);
        }

        let trusted = findings.is_empty() || sev <= Severity::Low;
        if !trusted {
            self.total_failures.fetch_add(1, Ordering::Relaxed);
            { let mut rc = self.pass_rate_computer.write(); rc.push((build.build_id.clone(), 1.0)); }
            let cats = findings.join("; ");
            warn!(build = %build.build_id, findings = %cats, "Build integrity issue");
            // MITRE ATT&CK cross-correlation
            let techniques = mitre::mitre_mapper().lookup("build_tampering");
            for tech in &techniques {
                mitre::correlator().ingest("build_integrity", &build.build_id, tech.tactic, &tech.technique_id, sev as u8 as f64 / 3.0, &build.build_id);
            }
            self.record_audit(&format!("fail|{}|{:?}|{}", build.build_id, sev, &cats[..cats.len().min(200)]));
            self.add_alert(now, sev, "Build integrity", &format!("{}: {}", build.build_id, &cats[..cats.len().min(200)]));
        } else {
            { let mut rc = self.pass_rate_computer.write(); rc.push((build.build_id.clone(), 0.0)); }
        }

        let mut builds = self.builds.write();
        if builds.len() >= MAX_ALERTS { builds.remove(0); }
        builds.push(build.clone());

        BuildVerdict { trusted, findings, severity: sev }
    }

    pub fn record_build(&self, build: BuildRecord) {
        self.verify_build(&build, "", "");
    }

    fn record_audit(&self, entry: &str) {
        let compressed = compression::compress_lz4(entry.as_bytes());
        let mut audit = self.compressed_audit.write();
        if audit.len() >= MAX_RECORDS { let half = audit.len() / 2; audit.drain(..half); }
        audit.push(compressed);
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(SupplyChainAlert { timestamp: ts, severity: sev, component: "build_integrity".into(), title: title.into(), details: details.into() });
    }

    pub fn total_builds(&self) -> u64 { self.total_builds.load(Ordering::Relaxed) }
    pub fn total_failures(&self) -> u64 { self.total_failures.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<SupplyChainAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }

    pub fn report(&self) -> BuildIntegrityReport {
        let builds = self.total_builds.load(Ordering::Relaxed);
        let failures = self.total_failures.load(Ordering::Relaxed);
        { let mut h = self.history.write(); h.checkpoint(BuildWindowSummary { builds, failures }); }
        BuildIntegrityReport {
            total_builds: builds, total_failures: failures,
            pass_rate_pct: if builds == 0 { 100.0 } else { (builds - failures) as f64 / builds as f64 * 100.0 },
        }
    }
}
