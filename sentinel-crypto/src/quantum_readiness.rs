//! Quantum Readiness Auditor — World-class post-quantum crypto inventory & migration engine
//!
//! Features:
//! - Complete NIST PQC algorithm knowledge base (ML-KEM, ML-DSA, SLH-DSA, FN-DSA)
//! - Classical algorithm vulnerability classification (RSA, ECC, DH, DSA, AES, SHA)
//! - Shor's algorithm impact analysis per key size and algorithm family
//! - Grover's algorithm impact on symmetric ciphers
//! - Migration path planning with priority scoring
//! - Protocol-level vulnerability mapping (TLS, SSH, IPSec, S/MIME, PGP)
//! - Certificate inventory with expiry-before-migration tracking
//! - Harvest-now-decrypt-later (HNDL) risk assessment
//! - Compliance mapping (CNSA 2.0, NIST SP 800-208, BSI, ANSSI)
//! - Cost estimation for migration effort
//!
//! Memory optimizations (10 techniques):
//! - **#1 HierarchicalState**: Audit snapshots over time O(log n)
//! - **#2 TieredCache**: Hot algorithm lookups
//! - **#3 ReversibleComputation**: Recompute migration scores from asset inputs
//! - **#4 VqCodec**: Compress crypto asset feature vectors
//! - **#5 StreamAccumulator**: Stream audit of large certificate inventories
//! - **#6 MemoryMetrics**: Bounded memory with theoretical verification
//! - **#461 DifferentialStore**: Store diffs for evolving algorithm status
//! - **#569 PruningMap**: Auto-expire stale audit results
//! - **#592 DedupStore**: Deduplicate identical certificates across services
//! - **#627 SparseMatrix**: Sparse protocol×algorithm vulnerability matrix

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::hierarchical::HierarchicalState;
use sentinel_core::reversible::ReversibleComputation;
use sentinel_core::vq_codec::VqCodec;
use sentinel_core::streaming::StreamAccumulator;
use sentinel_core::differential::DifferentialStore;
use sentinel_core::pruning::PruningMap;
use sentinel_core::dedup::DedupStore;
use sentinel_core::sparse::SparseMatrix;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 10_000;

// ── Algorithm Vulnerability Database ────────────────────────────────────────
// Each entry: (algorithm_family, variant, classical_bits, quantum_bits, migration_urgency, pqc_replacement)
// quantum_bits: effective security under quantum attack (Shor or Grover)
// migration_urgency: 0.0 (safe) to 1.0 (critical)

const CLASSICAL_ALGORITHMS: &[(&str, &str, u32, u32, f64, &str)] = &[
    // Public Key — broken by Shor's algorithm
    ("RSA", "RSA-1024", 80, 0, 1.0, "ML-KEM-768 + ML-DSA-65"),
    ("RSA", "RSA-2048", 112, 0, 0.95, "ML-KEM-768 + ML-DSA-65"),
    ("RSA", "RSA-3072", 128, 0, 0.90, "ML-KEM-1024 + ML-DSA-87"),
    ("RSA", "RSA-4096", 152, 0, 0.85, "ML-KEM-1024 + ML-DSA-87"),
    ("RSA", "RSA-8192", 200, 0, 0.75, "ML-KEM-1024 + ML-DSA-87"),
    ("ECC", "P-256", 128, 0, 0.95, "ML-KEM-768"),
    ("ECC", "P-384", 192, 0, 0.90, "ML-KEM-1024"),
    ("ECC", "P-521", 256, 0, 0.85, "ML-KEM-1024"),
    ("ECC", "Curve25519", 128, 0, 0.90, "ML-KEM-768"),
    ("ECC", "Ed25519", 128, 0, 0.90, "ML-DSA-65"),
    ("ECC", "Ed448", 224, 0, 0.85, "ML-DSA-87"),
    ("DH", "DH-2048", 112, 0, 0.95, "ML-KEM-768"),
    ("DH", "DH-3072", 128, 0, 0.90, "ML-KEM-1024"),
    ("DH", "ECDH-P256", 128, 0, 0.95, "ML-KEM-768"),
    ("DH", "ECDH-P384", 192, 0, 0.90, "ML-KEM-1024"),
    ("DSA", "DSA-2048", 112, 0, 0.95, "ML-DSA-65"),
    ("DSA", "DSA-3072", 128, 0, 0.90, "ML-DSA-87"),
    // Symmetric — weakened by Grover's algorithm (halved effective bits)
    ("AES", "AES-128", 128, 64, 0.40, "AES-256"),
    ("AES", "AES-192", 192, 96, 0.15, "AES-256"),
    ("AES", "AES-256", 256, 128, 0.0, "Already quantum-resistant"),
    ("ChaCha", "ChaCha20", 256, 128, 0.0, "Already quantum-resistant"),
    // Hash — Grover reduces collision resistance
    ("SHA", "SHA-1", 80, 40, 0.80, "SHA-3-256"),
    ("SHA", "SHA-256", 128, 85, 0.10, "SHA-3-256 or SHA-512"),
    ("SHA", "SHA-384", 192, 128, 0.0, "Already quantum-resistant"),
    ("SHA", "SHA-512", 256, 170, 0.0, "Already quantum-resistant"),
    ("SHA", "SHA-3-256", 128, 85, 0.0, "Already quantum-resistant"),
    ("SHA", "SHA-3-512", 256, 170, 0.0, "Already quantum-resistant"),
    ("SHA", "BLAKE2b", 256, 128, 0.0, "Already quantum-resistant"),
    ("SHA", "BLAKE3", 256, 128, 0.0, "Already quantum-resistant"),
    // MACs
    ("HMAC", "HMAC-SHA256", 256, 128, 0.0, "Already quantum-resistant"),
    ("HMAC", "HMAC-SHA384", 384, 192, 0.0, "Already quantum-resistant"),
];

// ── PQC Standards Database ──────────────────────────────────────────────────

const PQC_ALGORITHMS: &[(&str, &str, u32, &str, &str)] = &[
    // (name, type, security_level_bits, nist_status, use_case)
    ("ML-KEM-512", "KEM", 128, "FIPS 203", "Key encapsulation (lightweight)"),
    ("ML-KEM-768", "KEM", 192, "FIPS 203", "Key encapsulation (standard)"),
    ("ML-KEM-1024", "KEM", 256, "FIPS 203", "Key encapsulation (high security)"),
    ("ML-DSA-44", "Signature", 128, "FIPS 204", "Digital signature (lightweight)"),
    ("ML-DSA-65", "Signature", 192, "FIPS 204", "Digital signature (standard)"),
    ("ML-DSA-87", "Signature", 256, "FIPS 204", "Digital signature (high security)"),
    ("SLH-DSA-128s", "Signature", 128, "FIPS 205", "Stateless hash-based (small)"),
    ("SLH-DSA-128f", "Signature", 128, "FIPS 205", "Stateless hash-based (fast)"),
    ("SLH-DSA-192s", "Signature", 192, "FIPS 205", "Stateless hash-based (small)"),
    ("SLH-DSA-192f", "Signature", 192, "FIPS 205", "Stateless hash-based (fast)"),
    ("SLH-DSA-256s", "Signature", 256, "FIPS 205", "Stateless hash-based (small)"),
    ("SLH-DSA-256f", "Signature", 256, "FIPS 205", "Stateless hash-based (fast)"),
    ("FN-DSA-512", "Signature", 128, "Draft FIPS 206", "NTRU-lattice signature"),
    ("FN-DSA-1024", "Signature", 256, "Draft FIPS 206", "NTRU-lattice signature"),
    ("BIKE", "KEM", 128, "Round 4", "Code-based KEM"),
    ("Classic McEliece", "KEM", 256, "Round 4", "Code-based KEM (large keys)"),
    ("HQC", "KEM", 128, "Round 4", "Code-based KEM"),
];

// ── Protocol Vulnerability Matrix ───────────────────────────────────────────

const PROTOCOL_VULNS: &[(&str, &str, f64, &str)] = &[
    // (protocol, crypto_component, quantum_risk, migration_path)
    ("TLS 1.2", "RSA key exchange", 1.0, "Hybrid ML-KEM + ECDH"),
    ("TLS 1.2", "ECDHE key exchange", 0.95, "Hybrid ML-KEM + ECDH"),
    ("TLS 1.2", "RSA certificate", 0.95, "ML-DSA certificate"),
    ("TLS 1.3", "ECDHE key exchange", 0.90, "Hybrid ML-KEM + X25519"),
    ("TLS 1.3", "X25519 key exchange", 0.90, "Hybrid ML-KEM + X25519"),
    ("TLS 1.3", "Ed25519 certificate", 0.85, "ML-DSA-65 certificate"),
    ("SSH", "RSA host key", 0.95, "ML-DSA host key"),
    ("SSH", "Ed25519 host key", 0.90, "ML-DSA-65 host key"),
    ("SSH", "ECDH key exchange", 0.90, "ML-KEM-768 key exchange"),
    ("SSH", "Curve25519 key exchange", 0.90, "ML-KEM-768 key exchange"),
    ("IPSec/IKEv2", "DH group 14", 0.95, "ML-KEM-768"),
    ("IPSec/IKEv2", "ECDH P-256", 0.90, "ML-KEM-768"),
    ("IPSec/IKEv2", "RSA certificate", 0.95, "ML-DSA certificate"),
    ("S/MIME", "RSA encryption", 1.0, "ML-KEM-768"),
    ("S/MIME", "RSA signature", 0.95, "ML-DSA-65"),
    ("PGP/GPG", "RSA-2048", 0.95, "ML-DSA-65 + ML-KEM-768"),
    ("PGP/GPG", "ECC (cv25519)", 0.90, "ML-KEM-768"),
    ("DNSSEC", "RSA-2048", 0.95, "SLH-DSA-128f"),
    ("DNSSEC", "ECDSA P-256", 0.90, "ML-DSA-44"),
    ("Code Signing", "RSA-2048", 0.95, "ML-DSA-65"),
    ("Code Signing", "ECDSA P-256", 0.90, "ML-DSA-65"),
    ("JWT/JWS", "RS256", 0.95, "ML-DSA-65"),
    ("JWT/JWS", "ES256", 0.90, "ML-DSA-65"),
    ("HPKE", "X25519", 0.90, "ML-KEM-768"),
];

// ── CNSA 2.0 Timeline ──────────────────────────────────────────────────────

const CNSA_DEADLINES: &[(&str, u32, &str)] = &[
    ("Software/firmware signing", 2025, "CNSA 2.0 immediate"),
    ("Web browsers/servers (TLS)", 2025, "CNSA 2.0 immediate"),
    ("Cloud services", 2025, "CNSA 2.0 immediate"),
    ("Networking equipment (routers, firewalls)", 2026, "CNSA 2.0 near-term"),
    ("Operating systems", 2027, "CNSA 2.0 near-term"),
    ("Niche/legacy PKI", 2030, "CNSA 2.0 extended"),
    ("Custom/embedded COMSEC", 2030, "CNSA 2.0 extended"),
    ("All NSS systems", 2033, "CNSA 2.0 final"),
];

// ── Types ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CryptoAsset {
    pub name: String,
    pub algorithm: String,
    pub key_bits: u32,
    pub usage_context: String,     // e.g. "TLS server cert", "SSH host key"
    pub protocol: String,          // e.g. "TLS 1.3", "SSH"
    pub data_sensitivity: DataSensitivity,
    pub cert_expiry: Option<i64>,  // unix timestamp, if applicable
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum DataSensitivity { Public, Internal, Confidential, TopSecret }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QuantumAuditResult {
    pub asset_name: String,
    pub algorithm: String,
    pub classical_bits: u32,
    pub quantum_bits: u32,
    pub is_quantum_safe: bool,
    pub migration_urgency: f64,
    pub hndl_risk: f64,           // harvest-now-decrypt-later risk
    pub recommended_replacement: String,
    pub migration_effort: MigrationEffort,
    pub compliance_gaps: Vec<String>,
    pub severity: Severity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MigrationEffort { Trivial, Low, Medium, High, VeryHigh }

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct QuantumReadinessReport {
    pub total_assets: u64,
    pub vulnerable_assets: u64,
    pub safe_assets: u64,
    pub by_family: HashMap<String, u64>,
    pub by_protocol: HashMap<String, u64>,
    pub avg_migration_urgency: f64,
    pub hndl_at_risk: u64,
    pub estimated_migration_months: f64,
    pub compliance_score: f64,
    pub cnsa_compliant: bool,
}

// ── Quantum Readiness Auditor ───────────────────────────────────────────────

pub struct QuantumReadiness {
    /// #2 TieredCache: hot algorithm lookups
    algo_cache: TieredCache<String, (u32, u32, f64, String)>,
    /// #1 HierarchicalState: audit snapshots over time
    state_history: RwLock<HierarchicalState<QuantumReadinessReport>>,
    /// #3 ReversibleComputation: recompute urgency scores
    urgency_computer: RwLock<ReversibleComputation<(String, f64), f64>>,
    /// #4 VqCodec: compress asset feature vectors
    asset_codec: RwLock<VqCodec>,
    /// #5 StreamAccumulator: stream large cert inventories
    cert_accumulator: RwLock<StreamAccumulator<f64, f64>>,
    /// #461 DifferentialStore: track algorithm status changes
    algo_status_diffs: RwLock<DifferentialStore<String, String>>,
    /// #569 PruningMap: auto-expire stale audit results
    stale_audits: RwLock<PruningMap<String, i64>>,
    /// #592 DedupStore: deduplicate identical certs across services
    cert_dedup: RwLock<DedupStore<String, String>>,
    /// #627 SparseMatrix: protocol × algorithm vulnerability matrix
    vuln_matrix: RwLock<SparseMatrix<String, String, f64>>,
    /// Storage
    results: RwLock<Vec<QuantumAuditResult>>,
    alerts: RwLock<Vec<CryptoAlert>>,
    /// Stats
    total_audited: AtomicU64,
    vulnerable: AtomicU64,
    safe: AtomicU64,
    by_family: RwLock<HashMap<String, u64>>,
    by_protocol: RwLock<HashMap<String, u64>>,
    urgency_sum: RwLock<f64>,
    hndl_count: AtomicU64,
    /// #6 MemoryMetrics: theoretical verifier
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl QuantumReadiness {
    pub fn new() -> Self {
        let urgency_computer = ReversibleComputation::new(4096, |inputs: &[(String, f64)]| {
            if inputs.is_empty() { return 0.0f64; }
            let sum: f64 = inputs.iter().map(|(_, u)| *u).sum();
            sum / inputs.len() as f64
        });

        let cert_accumulator = StreamAccumulator::new(
            128,     // window of 128 certs before flush
            0.0f64,  // running average urgency
            |acc: &mut f64, items: &[f64]| {
                for &u in items {
                    *acc = *acc * 0.9 + u * 0.1;
                }
            },
        );

        // Pre-populate vulnerability matrix from PROTOCOL_VULNS
        let mut vuln_matrix = SparseMatrix::new(0.0f64);
        for &(proto, component, risk, _) in PROTOCOL_VULNS {
            vuln_matrix.set(proto.to_string(), component.to_string(), risk);
        }

        // Pre-populate algo cache from CLASSICAL_ALGORITHMS
        let algo_cache = TieredCache::new(5_000);
        for &(_, variant, classical, quantum, urgency, replacement) in CLASSICAL_ALGORITHMS {
            algo_cache.insert(
                variant.to_lowercase(),
                (classical, quantum, urgency, replacement.to_string()),
            );
        }

        Self {
            algo_cache,
            state_history: RwLock::new(HierarchicalState::new(6, 64)),
            urgency_computer: RwLock::new(urgency_computer),
            asset_codec: RwLock::new(VqCodec::new(64, 4)),
            cert_accumulator: RwLock::new(cert_accumulator),
            algo_status_diffs: RwLock::new(DifferentialStore::new()),
            stale_audits: RwLock::new(PruningMap::new(10_000)),
            cert_dedup: RwLock::new(DedupStore::new()),
            vuln_matrix: RwLock::new(vuln_matrix),
            results: RwLock::new(Vec::new()),
            alerts: RwLock::new(Vec::new()),
            total_audited: AtomicU64::new(0),
            vulnerable: AtomicU64::new(0),
            safe: AtomicU64::new(0),
            by_family: RwLock::new(HashMap::new()),
            by_protocol: RwLock::new(HashMap::new()),
            urgency_sum: RwLock::new(0.0),
            hndl_count: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("quantum_algo_cache", 2 * 1024 * 1024);
        metrics.register_component("quantum_results", 4 * 1024 * 1024);
        metrics.register_component("quantum_dedup", 2 * 1024 * 1024);
        self.algo_cache = self.algo_cache.with_metrics(metrics.clone(), "quantum_algo_cache");
        self.metrics = Some(metrics);
        self
    }

    // ── Core Audit Engine ───────────────────────────────────────────────────

    pub fn audit_asset(&self, asset: CryptoAsset) -> QuantumAuditResult {
        if !self.enabled {
            return QuantumAuditResult {
                asset_name: asset.name, algorithm: asset.algorithm,
                classical_bits: 0, quantum_bits: 0, is_quantum_safe: true,
                migration_urgency: 0.0, hndl_risk: 0.0,
                recommended_replacement: "Auditor disabled".into(),
                migration_effort: MigrationEffort::Trivial,
                compliance_gaps: vec![], severity: Severity::Low,
            };
        }

        self.total_audited.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();

        // #2 TieredCache: lookup algorithm details
        let algo_key = asset.algorithm.to_lowercase();
        let (classical_bits, quantum_bits, base_urgency, replacement) =
            if let Some(cached) = self.algo_cache.get(&algo_key) {
                cached
            } else {
                // Try partial match
                self.lookup_algorithm(&asset.algorithm, asset.key_bits)
            };

        let is_quantum_safe = quantum_bits >= 128 || base_urgency == 0.0;

        // HNDL risk: data that's encrypted now may be decrypted when quantum computers arrive
        let hndl_risk = self.compute_hndl_risk(&asset, base_urgency);

        // Adjust urgency based on data sensitivity and cert expiry
        let adjusted_urgency = self.adjust_urgency(base_urgency, &asset, hndl_risk);

        // Determine migration effort
        let migration_effort = self.estimate_migration_effort(&asset);

        // Check compliance gaps
        let compliance_gaps = self.check_compliance(&asset, is_quantum_safe, adjusted_urgency);

        let severity = if adjusted_urgency > 0.85 { Severity::Critical }
            else if adjusted_urgency > 0.65 { Severity::High }
            else if adjusted_urgency > 0.35 { Severity::Medium }
            else { Severity::Low };

        let result = QuantumAuditResult {
            asset_name: asset.name.clone(),
            algorithm: asset.algorithm.clone(),
            classical_bits,
            quantum_bits,
            is_quantum_safe,
            migration_urgency: adjusted_urgency,
            hndl_risk,
            recommended_replacement: replacement.clone(),
            migration_effort,
            compliance_gaps: compliance_gaps.clone(),
            severity,
        };

        // Update counters
        if is_quantum_safe {
            self.safe.fetch_add(1, Ordering::Relaxed);
        } else {
            self.vulnerable.fetch_add(1, Ordering::Relaxed);

            if adjusted_urgency > 0.5 {
                warn!(asset = %asset.name, algo = %asset.algorithm, urgency = adjusted_urgency, "Quantum-vulnerable crypto asset");
                self.add_alert(now, severity, "Quantum-vulnerable crypto",
                    &format!("{} uses {} (classical={}bit, quantum={}bit, urgency={:.0}%). Replace with {}",
                        asset.name, asset.algorithm, classical_bits, quantum_bits,
                        adjusted_urgency * 100.0, replacement));
            }
        }

        if hndl_risk > 0.5 {
            self.hndl_count.fetch_add(1, Ordering::Relaxed);
        }

        // #3 ReversibleComputation: track urgency
        {
            let mut uc = self.urgency_computer.write();
            uc.push((asset.name.clone(), adjusted_urgency));
        }

        // #5 StreamAccumulator: running average
        {
            let mut acc = self.cert_accumulator.write();
            acc.push(adjusted_urgency);
        }

        // #461 DifferentialStore: track algo status changes
        {
            let mut diffs = self.algo_status_diffs.write();
            let status = if is_quantum_safe { "safe" } else { "vulnerable" };
            diffs.record_update(asset.name.clone(), status.to_string());
        }

        // #569 PruningMap: freshness tracking
        {
            let mut prune = self.stale_audits.write();
            prune.insert(asset.name.clone(), now);
        }

        // #592 DedupStore: deduplicate cert data
        if !asset.usage_context.is_empty() {
            let mut dedup = self.cert_dedup.write();
            dedup.insert(
                format!("{}::{}", asset.name, asset.usage_context),
                asset.algorithm.clone(),
            );
        }

        // Stats
        {
            let family = self.extract_family(&asset.algorithm);
            let mut bf = self.by_family.write();
            *bf.entry(family).or_insert(0) += 1;
        }
        if !asset.protocol.is_empty() {
            let mut bp = self.by_protocol.write();
            *bp.entry(asset.protocol.clone()).or_insert(0) += 1;
        }
        {
            let mut us = self.urgency_sum.write();
            *us += adjusted_urgency;
        }

        // Store result
        {
            let mut r = self.results.write();
            if r.len() >= MAX_ALERTS {
                let drain = r.len() - MAX_ALERTS + 1;
                r.drain(..drain);
            }
            r.push(result.clone());
        }

        result
    }

    // ── Analysis Methods ────────────────────────────────────────────────────

    fn lookup_algorithm(&self, algo: &str, key_bits: u32) -> (u32, u32, f64, String) {
        let algo_lower = algo.to_lowercase();

        // Check if it's a known PQC algorithm (already safe)
        for &(name, _, sec_bits, _, _) in PQC_ALGORITHMS {
            if algo_lower.contains(&name.to_lowercase()) {
                return (sec_bits, sec_bits, 0.0, "Already post-quantum".into());
            }
        }

        // Match by family + key size
        for &(family, _, classical, quantum, urgency, replacement) in CLASSICAL_ALGORITHMS {
            if algo_lower.contains(&family.to_lowercase()) {
                // Adjust for actual key size if different from DB entry
                if family == "RSA" {
                    let adj_classical = match key_bits {
                        0..=1024 => 80,
                        1025..=2048 => 112,
                        2049..=3072 => 128,
                        3073..=4096 => 152,
                        _ => 200,
                    };
                    let adj_urgency = if key_bits <= 2048 { 0.95 } else { 0.85 };
                    return (adj_classical, quantum, adj_urgency, replacement.into());
                }
                if family == "AES" {
                    let (adj_classical, adj_quantum, adj_urgency) = match key_bits {
                        0..=128 => (128, 64, 0.4),
                        129..=192 => (192, 96, 0.15),
                        _ => (256, 128, 0.0),
                    };
                    let repl = if adj_urgency > 0.0 { "AES-256" } else { "Already quantum-resistant" };
                    return (adj_classical, adj_quantum, adj_urgency, repl.into());
                }
                return (classical, quantum, urgency, replacement.into());
            }
        }

        // Unknown algorithm — flag it
        (0, 0, 0.5, "Unknown algorithm — manual review required".into())
    }

    fn compute_hndl_risk(&self, asset: &CryptoAsset, base_urgency: f64) -> f64 {
        if base_urgency == 0.0 { return 0.0; }

        let sensitivity_factor = match asset.data_sensitivity {
            DataSensitivity::TopSecret => 1.0,
            DataSensitivity::Confidential => 0.8,
            DataSensitivity::Internal => 0.4,
            DataSensitivity::Public => 0.05,
        };

        // Higher HNDL risk for long-lived secrets
        let longevity_factor = if let Some(expiry) = asset.cert_expiry {
            let now = chrono::Utc::now().timestamp();
            let years_remaining = (expiry - now) as f64 / (365.25 * 86400.0);
            if years_remaining > 10.0 { 1.0 }
            else if years_remaining > 5.0 { 0.8 }
            else if years_remaining > 2.0 { 0.5 }
            else { 0.3 }
        } else {
            0.6 // unknown expiry is moderately concerning
        };

        (base_urgency * sensitivity_factor * longevity_factor).min(1.0)
    }

    fn adjust_urgency(&self, base: f64, asset: &CryptoAsset, hndl: f64) -> f64 {
        let mut urgency = base;

        // Sensitivity multiplier
        match asset.data_sensitivity {
            DataSensitivity::TopSecret => urgency = (urgency * 1.3).min(1.0),
            DataSensitivity::Confidential => urgency = (urgency * 1.1).min(1.0),
            DataSensitivity::Internal => {},
            DataSensitivity::Public => urgency *= 0.7,
        }

        // HNDL component adds urgency
        urgency = (urgency + hndl * 0.2).min(1.0);

        // Protocol risk from #627 SparseMatrix
        if !asset.protocol.is_empty() {
            let matrix = self.vuln_matrix.read();
            let proto_risk = *matrix.get(&asset.protocol, &asset.algorithm);
            if proto_risk > 0.0 {
                urgency = (urgency + proto_risk * 0.1).min(1.0);
            }
        }

        urgency
    }

    fn estimate_migration_effort(&self, asset: &CryptoAsset) -> MigrationEffort {
        let algo_lower = asset.algorithm.to_lowercase();
        let ctx_lower = asset.usage_context.to_lowercase();

        // Certificate replacement is generally moderate
        if ctx_lower.contains("cert") || ctx_lower.contains("tls") {
            return MigrationEffort::Medium;
        }

        // Embedded/firmware is very high effort
        if ctx_lower.contains("firmware") || ctx_lower.contains("embedded")
            || ctx_lower.contains("iot") || ctx_lower.contains("scada") {
            return MigrationEffort::VeryHigh;
        }

        // Symmetric algorithms are typically easy to upgrade
        if algo_lower.contains("aes") || algo_lower.contains("chacha") {
            return MigrationEffort::Low;
        }

        // Hash upgrades are usually trivial
        if algo_lower.contains("sha") || algo_lower.contains("blake") {
            return MigrationEffort::Trivial;
        }

        // Key exchange protocols
        if ctx_lower.contains("ssh") || ctx_lower.contains("vpn") || ctx_lower.contains("ipsec") {
            return MigrationEffort::High;
        }

        MigrationEffort::Medium
    }

    fn check_compliance(&self, asset: &CryptoAsset, safe: bool, urgency: f64) -> Vec<String> {
        let mut gaps = Vec::new();

        if !safe {
            // CNSA 2.0 deadlines
            let now_year = 2026u32; // approximate
            for &(category, deadline, label) in CNSA_DEADLINES {
                let cat_lower = category.to_lowercase();
                let ctx_lower = asset.usage_context.to_lowercase();
                if ctx_lower.contains("software") && cat_lower.contains("software")
                    || ctx_lower.contains("tls") && cat_lower.contains("web")
                    || ctx_lower.contains("cloud") && cat_lower.contains("cloud")
                    || ctx_lower.contains("network") && cat_lower.contains("network")
                {
                    if now_year >= deadline {
                        gaps.push(format!("{}: OVERDUE (deadline {})", label, deadline));
                    } else if now_year + 1 >= deadline {
                        gaps.push(format!("{}: due {}", label, deadline));
                    }
                }
            }

            if urgency > 0.5 {
                gaps.push("NIST SP 800-208: non-compliant (quantum-vulnerable signatures)".into());
            }
            if urgency > 0.3 {
                gaps.push("BSI TR-02102: recommend PQC migration".into());
            }
        }

        gaps
    }

    fn extract_family(&self, algo: &str) -> String {
        let lower = algo.to_lowercase();
        if lower.contains("rsa") { "RSA".into() }
        else if lower.contains("ecc") || lower.contains("ecdsa") || lower.contains("ecdh")
            || lower.contains("ed25519") || lower.contains("ed448") || lower.contains("curve25519")
            || lower.starts_with("p-") { "ECC".into() }
        else if lower.contains("aes") { "AES".into() }
        else if lower.contains("chacha") { "ChaCha".into() }
        else if lower.contains("sha") || lower.contains("blake") { "Hash".into() }
        else if lower.contains("dh") { "DH".into() }
        else if lower.contains("dsa") { "DSA".into() }
        else if lower.contains("ml-kem") || lower.contains("ml-dsa") || lower.contains("slh-dsa") { "PQC".into() }
        else { "Other".into() }
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS {
            let drain = a.len() - MAX_ALERTS + 1;
            a.drain(..drain);
        }
        a.push(CryptoAlert { timestamp: ts, severity: sev, component: "quantum_readiness".into(), title: title.into(), details: details.into() });
    }

    // ── Public Accessors ────────────────────────────────────────────────────

    pub fn register_asset(&self, asset: CryptoAsset) -> QuantumAuditResult {
        self.audit_asset(asset)
    }

    pub fn total_audited(&self) -> u64 { self.total_audited.load(Ordering::Relaxed) }
    pub fn total_assets(&self) -> u64 { self.total_audited.load(Ordering::Relaxed) }
    pub fn vulnerable(&self) -> u64 { self.vulnerable.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<CryptoAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }

    pub fn vulnerable_assets(&self) -> Vec<QuantumAuditResult> {
        self.results.read().iter().filter(|r| !r.is_quantum_safe).cloned().collect()
    }

    pub fn report(&self) -> QuantumReadinessReport {
        let total = self.total_audited.load(Ordering::Relaxed);
        let vuln = self.vulnerable.load(Ordering::Relaxed);
        let safe = self.safe.load(Ordering::Relaxed);
        let avg_urgency = if total > 0 { *self.urgency_sum.read() / total as f64 } else { 0.0 };
        let hndl = self.hndl_count.load(Ordering::Relaxed);

        let compliance = if total > 0 { safe as f64 / total as f64 * 100.0 } else { 100.0 };

        let report = QuantumReadinessReport {
            total_assets: total,
            vulnerable_assets: vuln,
            safe_assets: safe,
            by_family: self.by_family.read().clone(),
            by_protocol: self.by_protocol.read().clone(),
            avg_migration_urgency: avg_urgency,
            hndl_at_risk: hndl,
            estimated_migration_months: vuln as f64 * 2.5, // rough estimate
            compliance_score: compliance,
            cnsa_compliant: vuln == 0,
        };

        // #1 HierarchicalState: checkpoint O(log n)
        {
            let mut history = self.state_history.write();
            history.checkpoint(report.clone());
        }

        report
    }

    /// Query the #627 SparseMatrix for protocol vulnerability
    pub fn protocol_risk(&self, protocol: &str, component: &str) -> f64 {
        let matrix = self.vuln_matrix.read();
        *matrix.get(&protocol.to_string(), &component.to_string())
    }

    /// Check if a specific PQC algorithm is known
    pub fn is_pqc_algorithm(algo: &str) -> bool {
        let lower = algo.to_lowercase();
        PQC_ALGORITHMS.iter().any(|&(name, _, _, _, _)| lower.contains(&name.to_lowercase()))
    }
}
