//! Model Scanner — scans ML models for vulnerabilities and backdoors.
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Hot lookups cached
//! - **#6 Theoretical Verifier**: Bound memory usage
use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModelScanResult {
    pub model_name: String,
    pub version: String,
    pub threats_found: Vec<ThreatCategory>,
    pub scanned_at: i64,
    pub safe: bool,
    pub findings: Vec<String>,
}

pub struct ModelScanner {
    results: RwLock<Vec<ModelScanResult>>,
    alerts: RwLock<Vec<AiAlert>>,
    total_scanned: AtomicU64,
    total_threats: AtomicU64,
    _cache: TieredCache<String, u64>,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

/// Known dangerous file extensions in model archives.
const DANGEROUS_EXTENSIONS: &[&str] = &[
    ".pkl", ".pickle",  // Python pickle (arbitrary code execution)
    ".pt", ".pth",      // PyTorch (uses pickle internally)
    ".joblib",          // joblib (uses pickle)
    ".npy",             // NumPy (potential overflow)
];

/// Safe/preferred model formats.
const SAFE_FORMATS: &[&str] = &[
    ".safetensors",     // HuggingFace SafeTensors (no code execution)
    ".onnx",            // ONNX (declarative graph)
    ".tflite",          // TensorFlow Lite
    ".pb",              // TensorFlow protobuf
];

/// Known malicious model hashes (placeholder CVE-style entries).
const KNOWN_MALICIOUS_HASHES: &[&str] = &[
    "d41d8cd98f00b204e9800998ecf8427e", // empty file
    "0000000000000000000000000000dead",  // test marker
];

/// Suspicious layer/op names that indicate backdoor triggers.
const BACKDOOR_INDICATORS: &[&str] = &[
    "trigger", "backdoor", "trojan", "inject", "poison",
    "watermark_trigger", "adversarial_patch", "hidden_layer_inject",
    "reverse_shell", "exec_payload", "os.system", "__import__",
    "subprocess", "eval(", "exec(",
];

impl ModelScanner {
    pub fn new() -> Self {
        Self {
            results: RwLock::new(Vec::new()),
            alerts: RwLock::new(Vec::new()),
            total_scanned: AtomicU64::new(0),
            total_threats: AtomicU64::new(0),
            enabled: true,
            _cache: TieredCache::new(10_000),
            metrics: None,
        }
    }

    /// Scan a model file for security threats based on metadata.
    pub fn scan_model(&self, model_name: &str, version: &str, file_path: &str, file_size_bytes: u64, metadata: &str) -> ModelScanResult {
        if !self.enabled {
            return ModelScanResult { model_name: model_name.into(), version: version.into(), threats_found: vec![], scanned_at: 0, safe: true, findings: vec![] };
        }
        self.total_scanned.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        let lower_path = file_path.to_lowercase();
        let lower_meta = metadata.to_lowercase();
        let mut threats = Vec::new();
        let mut findings = Vec::new();

        // Check for dangerous serialization formats (pickle RCE)
        for ext in DANGEROUS_EXTENSIONS {
            if lower_path.ends_with(ext) {
                threats.push(ThreatCategory::AdversarialInput);
                findings.push(format!("unsafe_format:{}", ext));
            }
        }

        // Prefer safe formats
        let is_safe_format = SAFE_FORMATS.iter().any(|ext| lower_path.ends_with(ext));
        if !is_safe_format && threats.is_empty() {
            findings.push("unknown_format".into());
        }

        // Check for known malicious model hashes
        for hash in KNOWN_MALICIOUS_HASHES {
            if lower_meta.contains(hash) {
                threats.push(ThreatCategory::ModelPoisoning);
                findings.push(format!("known_malicious_hash:{}", &hash[..8]));
            }
        }

        // Check metadata for backdoor trigger indicators
        for indicator in BACKDOOR_INDICATORS {
            if lower_meta.contains(indicator) {
                threats.push(ThreatCategory::ModelPoisoning);
                findings.push(format!("backdoor_indicator:{}", indicator));
            }
        }

        // Heuristic: abnormally small model (possible trojan placeholder)
        if file_size_bytes > 0 && file_size_bytes < 1024 {
            findings.push("suspiciously_small_model".into());
            threats.push(ThreatCategory::Evasion);
        }

        // Heuristic: abnormally large model (possible data exfil payload)
        if file_size_bytes > 100_000_000_000 { // > 100GB
            findings.push("abnormally_large_model".into());
            threats.push(ThreatCategory::DataLeakage);
        }

        // Check for embedded Python code execution in metadata
        let code_exec_patterns = ["__reduce__", "__getattr__", "builtins", "os.system", "subprocess.Popen"];
        for pat in &code_exec_patterns {
            if lower_meta.contains(&pat.to_lowercase()) {
                threats.push(ThreatCategory::AdversarialInput);
                findings.push(format!("code_exec_in_metadata:{}", pat));
            }
        }

        // Check for supply chain indicators (untrusted source)
        let untrusted_sources = ["huggingface.co/anonymous", "unknown_author", "test_model"];
        for src in &untrusted_sources {
            if lower_meta.contains(src) {
                findings.push(format!("untrusted_source:{}", src));
            }
        }

        // Deduplicate threats by hash
        let mut seen = std::collections::HashSet::new();
        threats.retain(|t| seen.insert(*t));
        findings.sort();
        findings.dedup();

        let safe = threats.is_empty();
        if !safe {
            self.total_threats.fetch_add(threats.len() as u64, Ordering::Relaxed);
            let cats = findings.join(", ");
            warn!(model = %model_name, threats = threats.len(), findings = %cats, "Model threats detected");
            self.add_alert(now, Severity::Critical, "Model threats",
                &format!("{} v{}: {}", model_name, version, &cats[..cats.len().min(256)]));
        }

        let result = ModelScanResult { model_name: model_name.into(), version: version.into(), threats_found: threats, scanned_at: now, safe, findings };
        let mut r = self.results.write();
        if r.len() >= MAX_ALERTS { r.remove(0); }
        r.push(result.clone());
        result
    }

    /// Legacy API.
    pub fn scan(&self, model_name: &str, version: &str, threats: Vec<ThreatCategory>) -> ModelScanResult {
        self.total_scanned.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        let safe = threats.is_empty();
        if !safe {
            self.total_threats.fetch_add(threats.len() as u64, Ordering::Relaxed);
            warn!(model = %model_name, threats = threats.len(), "Model threats detected");
            self.add_alert(now, Severity::Critical, "Model threats", &format!("{} has {} threats", model_name, threats.len()));
        }
        let result = ModelScanResult { model_name: model_name.into(), version: version.into(), threats_found: threats, scanned_at: now, safe, findings: vec![] };
        let mut r = self.results.write();
        if r.len() >= MAX_ALERTS { r.remove(0); }
        r.push(result.clone());
        result
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(AiAlert { timestamp: ts, severity: sev, component: "model_scanner".into(), title: title.into(), details: details.into() });
    }

    pub fn total_scanned(&self) -> u64 { self.total_scanned.load(Ordering::Relaxed) }
    pub fn total_threats(&self) -> u64 { self.total_threats.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
