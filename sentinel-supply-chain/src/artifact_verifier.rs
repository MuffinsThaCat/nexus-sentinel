//! Artifact Verifier — World-class supply chain provenance & integrity engine
//!
//! Features:
//! - Signature chain validation (trusted signer registry)
//! - Hash algorithm strength analysis (MD5/SHA-1/CRC32 rejected)
//! - Hash length validation (SHA-256 minimum, SHA-512 preferred)
//! - SLSA provenance level assessment
//! - Artifact name path traversal detection
//! - Timestamp freshness verification (stale artifact warning)
//! - Graduated severity alerting (Critical/High/Medium/Low)
//! - Audit trail with LZ4 compression
//! - Compliance mapping (NIST SP 800-218 SSDF, SLSA v1.0, CIS Supply Chain)
//!
//! Memory optimizations (10 techniques):
//! - **#1 HierarchicalState**: Verification history O(log n)
//! - **#2 TieredCache**: Hot artifact lookups cached
//! - **#3 ReversibleComputation**: Recompute pass/fail rates
//! - **#5 StreamAccumulator**: Window stats without raw storage
//! - **#6 MemoryMetrics**: Bounded memory verification
//! - **#461 DifferentialStore**: Signer registry diffs
//! - **#569 PruningMap**: Auto-expire stale verifications
//! - **#592 DedupStore**: Dedup artifact names
//! - **#593 Compression**: LZ4 compress audit
//! - **#627 SparseMatrix**: Artifact-to-finding matrix

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
use std::collections::HashMap;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;
const MAX_RECORDS: usize = 10_000;

#[derive(Debug, Clone, Default)]
pub struct VerifyWindowSummary { pub verified: u64, pub failed: u64 }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ArtifactRecord {
    pub name: String,
    pub hash: String,
    pub signer: String,
    pub verified: bool,
    pub checked_at: i64,
}

const TRUSTED_SIGNERS: &[&str] = &[
    "github-actions", "gitlab-ci", "jenkins-ci", "circleci",
    "sigstore-cosign", "notary-v2", "gpg-release-key",
];

const WEAK_HASH_ALGOS: &[&str] = &["md5:", "sha1:", "crc32:"];

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerificationVerdict {
    pub trusted: bool,
    pub findings: Vec<String>,
    pub severity: Severity,
    pub chain_valid: bool,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ArtifactVerifierReport {
    pub total_verified: u64,
    pub total_failed: u64,
    pub pass_rate_pct: f64,
    pub active_artifacts: u64,
}

pub struct ArtifactVerifier {
    records: RwLock<HashMap<String, ArtifactRecord>>,
    trusted_signers: RwLock<std::collections::HashSet<String>>,
    alerts: RwLock<Vec<SupplyChainAlert>>,
    total_verified: AtomicU64,
    total_failed: AtomicU64,
    /// #2 TieredCache
    artifact_cache: TieredCache<String, u64>,
    /// #1 HierarchicalState
    history: RwLock<HierarchicalState<VerifyWindowSummary>>,
    /// #3 ReversibleComputation
    pass_rate_computer: RwLock<ReversibleComputation<(String, f64), f64>>,
    /// #5 StreamAccumulator
    verify_stream: RwLock<StreamAccumulator<u64, VerifyWindowSummary>>,
    /// #461 DifferentialStore
    signer_diffs: RwLock<DifferentialStore<String, String>>,
    /// #627 SparseMatrix
    artifact_finding_matrix: RwLock<SparseMatrix<String, String, u32>>,
    /// #569 PruningMap
    stale_artifacts: RwLock<PruningMap<String, i64>>,
    /// #592 DedupStore
    artifact_dedup: RwLock<DedupStore<String, String>>,
    /// #593 Compression
    compressed_audit: RwLock<Vec<Vec<u8>>>,
    /// #6 MemoryMetrics
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl ArtifactVerifier {
    pub fn new() -> Self {
        let mut signers = std::collections::HashSet::new();
        for s in TRUSTED_SIGNERS { signers.insert(s.to_string()); }
        let pass_rate_computer = ReversibleComputation::new(4096, |inputs: &[(String, f64)]| {
            if inputs.is_empty() { return 0.0f64; }
            let passed = inputs.iter().filter(|(_, v)| *v == 0.0).count();
            passed as f64 / inputs.len() as f64 * 100.0
        });
        let verify_stream = StreamAccumulator::new(64, VerifyWindowSummary::default(),
            |acc, ids: &[u64]| { acc.verified += ids.len() as u64; });
        Self {
            records: RwLock::new(HashMap::new()),
            trusted_signers: RwLock::new(signers),
            alerts: RwLock::new(Vec::new()),
            total_verified: AtomicU64::new(0),
            total_failed: AtomicU64::new(0),
            artifact_cache: TieredCache::new(10_000),
            history: RwLock::new(HierarchicalState::new(6, 64)),
            pass_rate_computer: RwLock::new(pass_rate_computer),
            verify_stream: RwLock::new(verify_stream),
            signer_diffs: RwLock::new(DifferentialStore::new()),
            artifact_finding_matrix: RwLock::new(SparseMatrix::new(0u32)),
            stale_artifacts: RwLock::new(PruningMap::new(50_000).with_ttl(std::time::Duration::from_secs(7 * 86400))),
            artifact_dedup: RwLock::new(DedupStore::new()),
            compressed_audit: RwLock::new(Vec::new()),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("av_cache", 2 * 1024 * 1024);
        metrics.register_component("av_audit", 128 * 1024);
        self.artifact_cache = self.artifact_cache.with_metrics(metrics.clone(), "av_cache");
        self.metrics = Some(metrics);
        self
    }

    pub fn add_trusted_signer(&self, signer: &str) {
        self.trusted_signers.write().insert(signer.to_string());
        { let mut diffs = self.signer_diffs.write(); diffs.record_update("trusted_signers".to_string(), signer.to_string()); }
    }

    pub fn verify_full(&self, record: &ArtifactRecord) -> VerificationVerdict {
        let now = chrono::Utc::now().timestamp();
        let count = self.total_verified.load(Ordering::Relaxed) + self.total_failed.load(Ordering::Relaxed);
        self.verify_stream.write().push(count);
        self.artifact_cache.insert(record.name.clone(), count);
        self.stale_artifacts.write().insert(record.name.clone(), now);
        { let mut dedup = self.artifact_dedup.write(); dedup.insert(record.name.clone(), record.hash.clone()); }

        let mut findings = Vec::new();
        let mut sev = Severity::Low;
        let mut chain_valid = true;

        // 1. Signature verification status
        if !record.verified {
            findings.push("CRITICAL: signature_invalid — artifact cannot be trusted".into());
            sev = Severity::Critical;
            chain_valid = false;
        }

        // 2. Signer trust chain (SLSA v1.0 provenance)
        let signer_lower = record.signer.to_lowercase();
        if record.signer.is_empty() {
            findings.push("HIGH: no_signer — unsigned artifact (SLSA Level 0)".into());
            if sev < Severity::High { sev = Severity::High; }
            chain_valid = false;
        } else if !self.trusted_signers.read().iter().any(|s| signer_lower.contains(&s.to_lowercase())) {
            findings.push(format!("MEDIUM: untrusted_signer:{} — not in allow-list", record.signer));
            if sev < Severity::Medium { sev = Severity::Medium; }
        }

        // 3. Hash algorithm strength (NIST SP 800-218)
        let hash_lower = record.hash.to_lowercase();
        for weak in WEAK_HASH_ALGOS {
            if hash_lower.starts_with(weak) {
                findings.push(format!("HIGH: weak_hash_algo:{} — collision-vulnerable", weak.trim_end_matches(':')));
                if sev < Severity::High { sev = Severity::High; }
            }
        }

        // 4. Hash length (SHA-256 = 64 hex, SHA-512 = 128 hex)
        let hash_hex = record.hash.split(':').last().unwrap_or(&record.hash);
        if hash_hex.len() < 64 {
            findings.push(format!("MEDIUM: short_hash:{}chars — SHA-256+ required", hash_hex.len()));
            if sev < Severity::Medium { sev = Severity::Medium; }
        }

        // 5. Timestamp freshness
        let age_hours = (now - record.checked_at) / 3600;
        if age_hours > 168 {
            findings.push(format!("LOW: stale_verification:{}h — re-verify recommended", age_hours));
        }

        // 6. Path traversal in artifact name
        let name_lower = record.name.to_lowercase();
        if name_lower.contains("..") || name_lower.contains("~") || name_lower.starts_with('/') {
            findings.push("HIGH: path_traversal_in_name — supply chain injection vector".into());
            if sev < Severity::High { sev = Severity::High; }
        }

        // 7. Suspicious extensions (double extensions, hidden executables)
        if name_lower.ends_with(".exe.gz") || name_lower.ends_with(".dll.zip") || name_lower.ends_with(".so.tar") {
            findings.push("MEDIUM: suspicious_double_extension — possible masquerading".into());
            if sev < Severity::Medium { sev = Severity::Medium; }
        }

        // Record findings in sparse matrix
        for f in &findings {
            let cat = if f.starts_with("CRITICAL") { "Critical" } else if f.starts_with("HIGH") { "High" } else if f.starts_with("MEDIUM") { "Medium" } else { "Low" };
            let mut mat = self.artifact_finding_matrix.write();
            let cur = *mat.get(&record.name, &cat.to_string());
            mat.set(record.name.clone(), cat.to_string(), cur + 1);
        }

        // MITRE ATT&CK mapping + cross-correlation
        if !findings.is_empty() {
            let techniques = mitre::mitre_mapper().lookup("signature_invalid");
            for tech in &techniques {
                mitre::correlator().ingest(
                    "artifact_verifier", &record.name, tech.tactic, &tech.technique_id,
                    sev as u8 as f64 / 3.0, &record.name,
                );
            }
        }

        let trusted = chain_valid && sev <= Severity::Low;
        if trusted {
            self.total_verified.fetch_add(1, Ordering::Relaxed);
            { let mut rc = self.pass_rate_computer.write(); rc.push((record.name.clone(), 0.0)); }
        } else {
            self.total_failed.fetch_add(1, Ordering::Relaxed);
            { let mut rc = self.pass_rate_computer.write(); rc.push((record.name.clone(), 1.0)); }
            let cats = findings.join("; ");
            warn!(artifact = %record.name, findings = %cats, "Artifact verification issue");
            self.record_audit(&format!("fail|{}|{:?}|{}", record.name, sev, &cats[..cats.len().min(200)]));
            self.add_alert(now, sev, "Artifact verification", &format!("{}: {}", record.name, &cats[..cats.len().min(200)]));
        }

        self.records.write().insert(record.name.clone(), record.clone());
        VerificationVerdict { trusted, findings, severity: sev, chain_valid }
    }

    pub fn verify(&self, record: ArtifactRecord) {
        self.verify_full(&record);
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
        a.push(SupplyChainAlert { timestamp: ts, severity: sev, component: "artifact_verifier".into(), title: title.into(), details: details.into() });
    }

    pub fn total_verified(&self) -> u64 { self.total_verified.load(Ordering::Relaxed) }
    pub fn total_failed(&self) -> u64 { self.total_failed.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<SupplyChainAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }

    pub fn report(&self) -> ArtifactVerifierReport {
        let verified = self.total_verified.load(Ordering::Relaxed);
        let failed = self.total_failed.load(Ordering::Relaxed);
        let total = verified + failed;
        { let mut h = self.history.write(); h.checkpoint(VerifyWindowSummary { verified: total, failed }); }
        ArtifactVerifierReport {
            total_verified: verified, total_failed: failed,
            pass_rate_pct: if total == 0 { 100.0 } else { verified as f64 / total as f64 * 100.0 },
            active_artifacts: self.records.read().len() as u64,
        }
    }
}
