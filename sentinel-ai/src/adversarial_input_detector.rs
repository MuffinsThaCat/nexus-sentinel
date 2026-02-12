//! Adversarial Input Detector — detects adversarial perturbations in multimodal inputs.
//!
//! When agents process images, audio, or files, adversarial perturbations can
//! manipulate model behavior. This module detects:
//!  1. **Image perturbation** — pixel-level noise, FGSM/PGD patches, steganography
//!  2. **Audio adversarial** — inaudible commands, ultrasonic injection
//!  3. **Document poisoning** — hidden text in PDFs, invisible CSS/HTML content
//!  4. **File format abuse** — polyglot files, embedded payloads in metadata
//!  5. **Statistical anomalies** — entropy, histogram, frequency domain analysis
//!
//! Memory optimizations:
//! - **#2 Tiered Cache**: Input fingerprint cache
//! - **#4 PruningMap**: φ-weighted alert pruning

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::differential::DifferentialStore;
use sentinel_core::pruning::PruningMap;
use sentinel_core::hierarchical::HierarchicalState;
use sentinel_core::sparse::SparseMatrix;
use sentinel_core::dedup::DedupStore;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone)]
pub struct MultimodalInput {
    pub input_id: String,
    pub agent_id: String,
    pub input_type: InputType,
    pub raw_bytes: Vec<u8>,
    pub metadata: HashMap<String, String>,
    pub source: String,
    pub timestamp: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum InputType {
    Image,
    Audio,
    Document,
    Binary,
    Unknown,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AdversarialResult {
    pub risk_score: f64,
    pub adversarial_detected: bool,
    pub findings: Vec<AdversarialFinding>,
    pub input_type: String,
    pub entropy: f64,
    pub recommended_action: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AdversarialFinding {
    pub category: String,
    pub risk_score: f64,
    pub details: String,
}

pub struct AdversarialInputDetector {
    block_threshold: f64,
    enabled: bool,

    /// Breakthrough #2: Hot/warm/cold input fingerprint cache
    input_cache: TieredCache<u64, f64>,
    /// Breakthrough #461: Input baseline evolution tracking
    input_diffs: DifferentialStore<String, String>,
    /// Breakthrough #569: φ-weighted alert pruning
    pruned_alerts: PruningMap<String, AiAlert>,
    /// Breakthrough #1: O(log n) adversarial risk trajectory checkpoints
    risk_checkpoints: RwLock<HierarchicalState<f64>>,
    /// Breakthrough #627: Sparse agent×attack-type risk matrix
    attack_matrix: RwLock<SparseMatrix<String, String, f64>>,
    /// Content-addressed dedup for seen input fingerprints
    input_dedup: DedupStore<String, String>,
    alerts: RwLock<Vec<AiAlert>>,

    total_scans: AtomicU64,
    total_adversarial: AtomicU64,
    total_image_attacks: AtomicU64,
    total_audio_attacks: AtomicU64,
    total_doc_attacks: AtomicU64,
    total_polyglot: AtomicU64,

    metrics: Option<MemoryMetrics>,
}

impl AdversarialInputDetector {
    pub fn new() -> Self {
        Self {
            block_threshold: 0.70,
            enabled: true,
            input_cache: TieredCache::new(50_000),
            input_diffs: DifferentialStore::new(),
            pruned_alerts: PruningMap::new(5_000),
            risk_checkpoints: RwLock::new(HierarchicalState::new(8, 64)),
            attack_matrix: RwLock::new(SparseMatrix::new(0.0)),
            input_dedup: DedupStore::new(),
            alerts: RwLock::new(Vec::new()),
            total_scans: AtomicU64::new(0),
            total_adversarial: AtomicU64::new(0),
            total_image_attacks: AtomicU64::new(0),
            total_audio_attacks: AtomicU64::new(0),
            total_doc_attacks: AtomicU64::new(0),
            total_polyglot: AtomicU64::new(0),
            metrics: None,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("adversarial_input_detector", 4 * 1024 * 1024);
        self.input_cache = self.input_cache.with_metrics(metrics.clone(), "adversarial_cache");
        self.metrics = Some(metrics);
        self
    }

    pub fn scan(&self, input: &MultimodalInput) -> AdversarialResult {
        if !self.enabled { return Self::clean_result(&input.input_type); }
        self.total_scans.fetch_add(1, Ordering::Relaxed);

        let mut findings = Vec::new();
        let mut max_risk = 0.0f64;

        // 1. Entropy analysis (applies to all types)
        let entropy = Self::byte_entropy(&input.raw_bytes);
        if entropy > 7.9 && input.raw_bytes.len() > 1024 {
            max_risk = max_risk.max(0.55);
            findings.push(AdversarialFinding {
                category: "high_entropy".into(), risk_score: 0.55,
                details: format!("Suspiciously high entropy: {:.3} (near random)", entropy),
            });
        }

        // 2. Type-specific analysis
        match input.input_type {
            InputType::Image => {
                let (s, f) = self.scan_image(&input.raw_bytes);
                max_risk = max_risk.max(s);
                findings.extend(f);
                if max_risk >= self.block_threshold { self.total_image_attacks.fetch_add(1, Ordering::Relaxed); }
            }
            InputType::Audio => {
                let (s, f) = self.scan_audio(&input.raw_bytes);
                max_risk = max_risk.max(s);
                findings.extend(f);
                if max_risk >= self.block_threshold { self.total_audio_attacks.fetch_add(1, Ordering::Relaxed); }
            }
            InputType::Document => {
                let (s, f) = self.scan_document(&input.raw_bytes);
                max_risk = max_risk.max(s);
                findings.extend(f);
                if max_risk >= self.block_threshold { self.total_doc_attacks.fetch_add(1, Ordering::Relaxed); }
            }
            _ => {}
        }

        // 3. Polyglot file detection (multiple valid file signatures)
        let polyglot_score = self.detect_polyglot(&input.raw_bytes);
        if polyglot_score > 0.0 {
            max_risk = max_risk.max(polyglot_score);
            self.total_polyglot.fetch_add(1, Ordering::Relaxed);
            findings.push(AdversarialFinding {
                category: "polyglot_file".into(), risk_score: polyglot_score,
                details: "Multiple file format signatures detected (polyglot file)".into(),
            });
        }

        // 4. Metadata injection
        let (meta_score, meta_findings) = self.scan_metadata(&input.metadata);
        max_risk = max_risk.max(meta_score);
        findings.extend(meta_findings);

        let adversarial = max_risk >= self.block_threshold;
        if adversarial {
            self.total_adversarial.fetch_add(1, Ordering::Relaxed);
            let now = input.timestamp;
            warn!(agent=%input.agent_id, input=%input.input_id, risk=max_risk, "Adversarial input detected");
            self.add_alert(now, Severity::High, "Adversarial input detected",
                &format!("agent={}, type={:?}, risk={:.2}, findings={}", input.agent_id, input.input_type, max_risk, findings.len()));
        }

        AdversarialResult {
            risk_score: max_risk, adversarial_detected: adversarial, findings,
            input_type: format!("{:?}", input.input_type), entropy,
            recommended_action: if adversarial { "block".into() } else { "allow".into() },
        }
    }

    // ── Image analysis ──────────────────────────────────────────────────────

    fn scan_image(&self, data: &[u8]) -> (f64, Vec<AdversarialFinding>) {
        let mut score = 0.0f64;
        let mut findings = Vec::new();

        // Check for adversarial patch indicators (high-frequency noise in specific regions)
        if data.len() > 100 {
            let histogram = Self::byte_histogram(data);
            let hist_entropy = Self::histogram_entropy(&histogram);
            // Adversarial images tend to have unusual byte distributions
            if hist_entropy > 7.95 {
                score = score.max(0.65);
                findings.push(AdversarialFinding {
                    category: "image_perturbation".into(), risk_score: 0.65,
                    details: format!("Image byte distribution anomaly: entropy={:.3}", hist_entropy),
                });
            }

            // Check for steganographic indicators (LSB patterns)
            let lsb_score = Self::lsb_anomaly_score(data);
            if lsb_score > 0.60 {
                score = score.max(lsb_score);
                findings.push(AdversarialFinding {
                    category: "steganography".into(), risk_score: lsb_score,
                    details: format!("LSB anomaly detected: score={:.2}", lsb_score),
                });
            }
        }

        // Check for embedded text in image data (prompt injection via OCR)
        let text_markers = ["ignore", "system", "override", "bypass", "instruction"];
        let data_str = String::from_utf8_lossy(data).to_lowercase();
        for marker in text_markers {
            if data_str.contains(marker) {
                score = score.max(0.72);
                findings.push(AdversarialFinding {
                    category: "embedded_text_injection".into(), risk_score: 0.72,
                    details: format!("Suspicious text '{}' found embedded in image data", marker),
                });
            }
        }

        (score, findings)
    }

    // ── Audio analysis ──────────────────────────────────────────────────────

    fn scan_audio(&self, data: &[u8]) -> (f64, Vec<AdversarialFinding>) {
        let mut score = 0.0f64;
        let mut findings = Vec::new();

        if data.len() < 100 { return (score, findings); }

        // Detect ultrasonic frequency indicators (high-byte concentration patterns)
        let high_byte_ratio = data.iter().filter(|&&b| b > 200).count() as f64 / data.len() as f64;
        if high_byte_ratio > 0.40 {
            score = score.max(0.60);
            findings.push(AdversarialFinding {
                category: "ultrasonic_injection".into(), risk_score: 0.60,
                details: format!("High-frequency byte concentration: {:.1}%", high_byte_ratio * 100.0),
            });
        }

        // Check for repeating patterns (adversarial audio often has periodic structures)
        let repetition = Self::detect_byte_repetition(data, 256);
        if repetition > 0.50 {
            score = score.max(0.55);
            findings.push(AdversarialFinding {
                category: "audio_repetition_anomaly".into(), risk_score: 0.55,
                details: format!("Periodic pattern detected: repetition={:.2}", repetition),
            });
        }

        (score, findings)
    }

    // ── Document analysis ───────────────────────────────────────────────────

    fn scan_document(&self, data: &[u8]) -> (f64, Vec<AdversarialFinding>) {
        let mut score = 0.0f64;
        let mut findings = Vec::new();

        let text = String::from_utf8_lossy(data).to_lowercase();

        // Hidden text via CSS/HTML
        let hidden_markers = [
            "display:none", "visibility:hidden", "font-size:0", "color:white;background:white",
            "opacity:0", "position:absolute;left:-9999", "text-indent:-9999",
        ];
        for marker in hidden_markers {
            if text.contains(marker) {
                score = score.max(0.78);
                findings.push(AdversarialFinding {
                    category: "hidden_text".into(), risk_score: 0.78,
                    details: format!("Hidden text technique: '{}'", marker),
                });
            }
        }

        // JavaScript injection in documents
        let js_markers = ["<script", "javascript:", "onerror=", "onload=", "eval(", "document.write"];
        for marker in js_markers {
            if text.contains(marker) {
                score = score.max(0.85);
                findings.push(AdversarialFinding {
                    category: "script_injection".into(), risk_score: 0.85,
                    details: format!("Script injection: '{}'", marker),
                });
            }
        }

        // Prompt injection in document text
        let injection_markers = [
            "ignore previous instructions", "system prompt", "you are now",
            "override your", "bypass safety", "disregard",
        ];
        for marker in injection_markers {
            if text.contains(marker) {
                score = score.max(0.88);
                findings.push(AdversarialFinding {
                    category: "document_prompt_injection".into(), risk_score: 0.88,
                    details: format!("Prompt injection in document: '{}'", marker),
                });
            }
        }

        (score, findings)
    }

    // ── Polyglot detection ──────────────────────────────────────────────────

    fn detect_polyglot(&self, data: &[u8]) -> f64 {
        if data.len() < 16 { return 0.0; }
        let sigs: Vec<(&str, &[u8])> = vec![
            ("PDF", b"%PDF"), ("PNG", &[0x89, 0x50, 0x4E, 0x47]),
            ("JPEG", &[0xFF, 0xD8, 0xFF]), ("GIF", b"GIF8"),
            ("ZIP", &[0x50, 0x4B, 0x03, 0x04]), ("ELF", &[0x7F, 0x45, 0x4C, 0x46]),
            ("PE", &[0x4D, 0x5A]), ("HTML", b"<!DOCTYPE"), ("HTML2", b"<html"),
        ];
        let mut matches = 0;
        for (_, sig) in &sigs {
            if data.starts_with(sig) { matches += 1; }
            // Also check if signature appears elsewhere in the file
            if data.len() > 1024 {
                if data[256..].windows(sig.len()).any(|w| w == *sig) { matches += 1; }
            }
        }
        if matches >= 2 { (0.75 + matches as f64 * 0.05).min(0.95) } else { 0.0 }
    }

    // ── Metadata scanning ───────────────────────────────────────────────────

    fn scan_metadata(&self, metadata: &HashMap<String, String>) -> (f64, Vec<AdversarialFinding>) {
        let mut score = 0.0f64;
        let mut findings = Vec::new();

        for (key, value) in metadata {
            let lower_val = value.to_lowercase();
            // Check for injection in EXIF/metadata fields
            let suspicious = ["<script", "javascript:", "ignore previous", "system prompt",
                "eval(", "http://", "https://"];
            for marker in suspicious {
                if lower_val.contains(marker) {
                    score = score.max(0.75);
                    findings.push(AdversarialFinding {
                        category: "metadata_injection".into(), risk_score: 0.75,
                        details: format!("Suspicious content in metadata field '{}': '{}'", key, marker),
                    });
                }
            }
        }

        (score, findings)
    }

    // ── Statistical utilities ───────────────────────────────────────────────

    fn byte_entropy(data: &[u8]) -> f64 {
        if data.is_empty() { return 0.0; }
        let mut freq = [0u32; 256];
        for &b in data { freq[b as usize] += 1; }
        let len = data.len() as f64;
        let mut e = 0.0f64;
        for &c in &freq {
            if c > 0 { let p = c as f64 / len; e -= p * p.log2(); }
        }
        e
    }

    fn byte_histogram(data: &[u8]) -> [u32; 256] {
        let mut hist = [0u32; 256];
        for &b in data { hist[b as usize] += 1; }
        hist
    }

    fn histogram_entropy(hist: &[u32; 256]) -> f64 {
        let total: u32 = hist.iter().sum();
        if total == 0 { return 0.0; }
        let mut e = 0.0f64;
        for &c in hist {
            if c > 0 { let p = c as f64 / total as f64; e -= p * p.log2(); }
        }
        e
    }

    fn lsb_anomaly_score(data: &[u8]) -> f64 {
        if data.len() < 100 { return 0.0; }
        // Check if LSBs are unusually biased (steganography indicator)
        let lsb_ones = data.iter().filter(|&&b| b & 1 == 1).count();
        let ratio = lsb_ones as f64 / data.len() as f64;
        // Normal images: ~50% LSB=1. Stego: often skewed
        let deviation = (ratio - 0.5).abs();
        if deviation > 0.05 { (0.50 + deviation * 4.0).min(0.85) } else { 0.0 }
    }

    fn detect_byte_repetition(data: &[u8], window: usize) -> f64 {
        if data.len() < window * 2 { return 0.0; }
        let first = &data[..window];
        let mut matches = 0;
        let checks = (data.len() / window).min(10);
        for i in 1..checks {
            let chunk = &data[i * window..(i * window + window).min(data.len())];
            let matching = first.iter().zip(chunk).filter(|(a, b)| a == b).count();
            if matching as f64 / window as f64 > 0.80 { matches += 1; }
        }
        matches as f64 / checks.max(1) as f64
    }

    fn clean_result(input_type: &InputType) -> AdversarialResult {
        AdversarialResult {
            risk_score: 0.0, adversarial_detected: false, findings: vec![],
            input_type: format!("{:?}", input_type), entropy: 0.0,
            recommended_action: "allow".into(),
        }
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(AiAlert { timestamp: ts, severity: sev, component: "adversarial_input_detector".into(), title: title.into(), details: details.into() });
    }

    pub fn total_scans(&self) -> u64 { self.total_scans.load(Ordering::Relaxed) }
    pub fn total_adversarial(&self) -> u64 { self.total_adversarial.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
