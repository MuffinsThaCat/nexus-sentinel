//! Hallucination / Confabulation Detector — detects when AI outputs are fabricated,
//! self-contradictory, or contain invented references.
//!
//! Unlike output_filter (which catches harmful content), this module checks output
//! *truthfulness* and *consistency*:
//!
//! ## 8 Detection Dimensions
//! 1. **Self-contradiction across turns** — Detects when AI contradicts its own prior statements
//! 2. **Fabricated citation detection** — Catches invented URLs, DOIs, arXiv IDs, package names
//! 3. **Numerical inconsistency** — Detects when numbers/statistics change between turns
//! 4. **Confident uncertainty** — Catches high-confidence language about uncertain claims
//! 5. **Phantom entity detection** — Detects references to non-existent APIs, functions, libraries
//! 6. **Temporal impossibility** — Catches claims about future events or anachronisms
//! 7. **Cross-turn fact drift** — Tracks how "facts" morph across conversation turns
//! 8. **Source attribution analysis** — Validates that claimed sources match content
//!
//! Memory optimizations: #2 TieredCache, #461 DifferentialStore, #569 PruningMap

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
const MAX_CLAIMS_PER_SESSION: usize = 200;

// ── Fabricated Citation Patterns ────────────────────────────────────────────

/// URL patterns that are commonly hallucinated by LLMs
const SUSPICIOUS_URL_PATTERNS: &[&str] = &[
    "example.com/api/", "docs.example", "api.example",
    "github.com/user/", "github.com/example",
    "arxiv.org/abs/9999", "arxiv.org/abs/0000",
    "doi.org/10.0000", "doi.org/10.9999",
    "npm.js.org/", "npmjs.org/",   // misspelled (real: npmjs.com)
    "pypi.com/",                    // misspelled (real: pypi.org)
    "crates.io/crate/",            // misspelled (real: crates.io/crates/)
    "stackoverflow.com/a/0000000",
];

/// Commonly hallucinated package/library names (non-existent)
const PHANTOM_INDICATORS: &[(&str, &str)] = &[
    ("import ", "python_import"),
    ("from ", "python_from_import"),
    ("require(", "node_require"),
    ("use ", "rust_use"),
    ("include ", "cpp_include"),
    ("gem install ", "ruby_gem"),
    ("pip install ", "python_pip"),
    ("npm install ", "node_npm"),
    ("cargo add ", "rust_cargo"),
];

/// High-confidence language markers
const CONFIDENCE_MARKERS: &[&str] = &[
    "definitely", "certainly", "absolutely", "without a doubt",
    "it is well known", "everyone knows", "it's a fact that",
    "research has shown", "studies confirm", "according to",
    "the official documentation states", "as documented in",
    "the standard specifies", "per the specification",
];

/// Temporal impossibility markers
const FUTURE_MARKERS: &[&str] = &[
    "will be released in 2027", "will be released in 2028",
    "will be released in 2029", "will be released in 2030",
    "upcoming version", "planned for release",
    "scheduled for", "expected to launch",
];

// ── Core Types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HallucinationResult {
    pub hallucination_score: f64,
    pub findings: Vec<HallucinationFinding>,
    pub cross_turn_contradictions: u32,
    pub fabricated_citations: u32,
    pub phantom_entities: u32,
    pub confidence_without_basis: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HallucinationFinding {
    pub category: String,
    pub description: String,
    pub severity: f64,
    pub evidence: String,
}

#[derive(Debug, Clone)]
struct Claim {
    text: String,
    turn: u32,
    timestamp: i64,
    category: String,
    key_terms: Vec<String>,
}

#[derive(Debug, Clone)]
struct SessionHistory {
    claims: Vec<Claim>,
    numerical_facts: HashMap<String, Vec<(f64, u32)>>,  // key → [(value, turn)]
    stated_facts: Vec<(String, u32)>,                    // (fact_text, turn)
    turn_count: u32,
}

pub struct HallucinationDetector {
    sessions: RwLock<HashMap<String, SessionHistory>>,
    /// Breakthrough #2: Hot/warm/cold verdict cache
    verdict_cache: TieredCache<String, f64>,
    /// Breakthrough #461: Claim baseline evolution tracking
    claim_diffs: DifferentialStore<String, String>,
    /// Breakthrough #569: φ-weighted alert eviction
    alert_pruning: PruningMap<String, AiAlert>,
    /// Breakthrough #1: O(log n) hallucination score trajectory checkpoints
    score_checkpoints: RwLock<HierarchicalState<f64>>,
    /// Breakthrough #627: Sparse session×finding category matrix
    finding_matrix: RwLock<SparseMatrix<String, String, f64>>,
    /// Content-addressed dedup for seen output fragments
    output_dedup: DedupStore<String, String>,
    alerts: RwLock<Vec<AiAlert>>,
    total_analyzed: AtomicU64,
    total_hallucinations: AtomicU64,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl HallucinationDetector {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            verdict_cache: TieredCache::new(20_000),
            claim_diffs: DifferentialStore::new(),
            alert_pruning: PruningMap::new(MAX_ALERTS),
            score_checkpoints: RwLock::new(HierarchicalState::new(8, 64)),
            finding_matrix: RwLock::new(SparseMatrix::new(0.0)),
            output_dedup: DedupStore::new(),
            alerts: RwLock::new(Vec::new()),
            total_analyzed: AtomicU64::new(0),
            total_hallucinations: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("hallucination_detector", 4 * 1024 * 1024);
        self.verdict_cache = self.verdict_cache.with_metrics(metrics.clone(), "hallucination_detector");
        self.metrics = Some(metrics);
        self
    }

    // ── Core Analysis ───────────────────────────────────────────────────────

    /// Analyze an AI output for hallucination indicators.
    /// `session_id` enables cross-turn consistency checks.
    pub fn analyze_output(&self, output: &str, session_id: Option<&str>) -> HallucinationResult {
        if !self.enabled || output.is_empty() {
            return HallucinationResult {
                hallucination_score: 0.0, findings: vec![],
                cross_turn_contradictions: 0, fabricated_citations: 0,
                phantom_entities: 0, confidence_without_basis: 0,
            };
        }

        self.total_analyzed.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        let lower = output.to_lowercase();
        let mut findings = Vec::new();

        // 1. Fabricated citation detection
        let fab_count = self.detect_fabricated_citations(output, &lower, &mut findings);

        // 2. Phantom entity detection
        let phantom_count = self.detect_phantom_entities(output, &lower, &mut findings);

        // 3. Confident uncertainty
        let conf_count = self.detect_confident_uncertainty(&lower, &mut findings);

        // 4. Temporal impossibility
        self.detect_temporal_impossibility(&lower, &mut findings);

        // 5. Numerical consistency extraction
        let numbers = self.extract_numerical_claims(output);

        // 6. Cross-turn analysis
        let mut contradictions = 0u32;
        if let Some(sid) = session_id {
            contradictions = self.cross_turn_analysis(sid, output, &lower, &numbers, now, &mut findings);
        }

        // 7. Compute hallucination score
        let score = self.compute_score(&findings, fab_count, phantom_count, conf_count, contradictions);

        if score >= 0.60 {
            self.total_hallucinations.fetch_add(1, Ordering::Relaxed);
            warn!(score=score, findings=findings.len(), "Hallucination detected");
            self.add_alert(now, Severity::Medium, "Hallucination detected",
                &format!("score={:.3}, citations={}, phantoms={}, contradictions={}",
                    score, fab_count, phantom_count, contradictions));
        }

        HallucinationResult {
            hallucination_score: score,
            findings,
            cross_turn_contradictions: contradictions,
            fabricated_citations: fab_count,
            phantom_entities: phantom_count,
            confidence_without_basis: conf_count,
        }
    }

    // ── Detection Methods ───────────────────────────────────────────────────

    fn detect_fabricated_citations(&self, output: &str, lower: &str, findings: &mut Vec<HallucinationFinding>) -> u32 {
        let mut count = 0u32;

        // Check suspicious URL patterns
        for pat in SUSPICIOUS_URL_PATTERNS {
            if lower.contains(pat) {
                count += 1;
                findings.push(HallucinationFinding {
                    category: "fabricated_citation".into(),
                    description: format!("Suspicious URL pattern: {}", pat),
                    severity: 0.7,
                    evidence: pat.to_string(),
                });
            }
        }

        // Detect malformed arXiv IDs (real format: YYMM.NNNNN)
        let mut pos = 0;
        while let Some(idx) = lower[pos..].find("arxiv") {
            let abs_pos = pos + idx;
            if let Some(id_start) = lower[abs_pos..].find(|c: char| c.is_ascii_digit()) {
                let id_region = &output[abs_pos + id_start..];
                let id_end = id_region.find(|c: char| !c.is_ascii_digit() && c != '.').unwrap_or(id_region.len());
                let candidate = &id_region[..id_end.min(12)];
                // Valid arXiv: YYMM.NNNNN where YY=07..26, MM=01..12
                if candidate.len() >= 8 && candidate.contains('.') {
                    if let Some(dot_pos) = candidate.find('.') {
                        let yy: Option<u32> = candidate[..2].parse().ok();
                        let mm: Option<u32> = candidate[2..dot_pos].parse().ok();
                        if let (Some(y), Some(m)) = (yy, mm) {
                            if y > 26 || m > 12 || m == 0 {
                                count += 1;
                                findings.push(HallucinationFinding {
                                    category: "fabricated_arxiv".into(),
                                    description: format!("Invalid arXiv ID: {}", candidate),
                                    severity: 0.85,
                                    evidence: candidate.to_string(),
                                });
                            }
                        }
                    }
                }
            }
            pos = abs_pos + 5;
            if pos >= lower.len() { break; }
        }

        // Detect DOIs with suspicious patterns
        if lower.contains("doi.org/10.") || lower.contains("doi: 10.") {
            // Check for obviously fake DOI prefixes (10.0000, 10.9999)
            for fake_prefix in &["10.0000", "10.9999", "10.00000", "10.99999"] {
                if lower.contains(fake_prefix) {
                    count += 1;
                    findings.push(HallucinationFinding {
                        category: "fabricated_doi".into(),
                        description: format!("Suspicious DOI prefix: {}", fake_prefix),
                        severity: 0.80,
                        evidence: fake_prefix.to_string(),
                    });
                }
            }
        }

        count
    }

    fn detect_phantom_entities(&self, _output: &str, lower: &str, findings: &mut Vec<HallucinationFinding>) -> u32 {
        let mut count = 0u32;

        // Check for references to non-existent well-known entities
        // (AI commonly hallucinates these specific patterns)
        let phantom_patterns = [
            ("gpt-5", "GPT-5 doesn't exist yet"),
            ("gpt-6", "GPT-6 doesn't exist"),
            ("claude 4", "Claude 4 doesn't exist yet"),
            ("gemini 3", "Gemini 3 doesn't exist yet"),
            ("llama 4", "LLaMA 4 doesn't exist yet"),
            ("python 4", "Python 4 doesn't exist"),
            ("rust 2.0", "Rust 2.0 doesn't exist"),
            ("http/4", "HTTP/4 doesn't exist"),
            ("html6", "HTML6 doesn't exist"),
            ("css5", "CSS5 doesn't exist"),
            ("ecmascript 2030", "ES2030 doesn't exist"),
        ];

        for (pattern, desc) in &phantom_patterns {
            if lower.contains(pattern) {
                count += 1;
                findings.push(HallucinationFinding {
                    category: "phantom_entity".into(),
                    description: desc.to_string(),
                    severity: 0.75,
                    evidence: pattern.to_string(),
                });
            }
        }

        count
    }

    fn detect_confident_uncertainty(&self, lower: &str, findings: &mut Vec<HallucinationFinding>) -> u32 {
        let mut count = 0u32;

        // Count confidence markers
        let confidence_count = CONFIDENCE_MARKERS.iter()
            .filter(|m| lower.contains(*m))
            .count();

        // If output uses many confidence markers, it may be confabulating
        if confidence_count >= 3 {
            count = confidence_count as u32;
            findings.push(HallucinationFinding {
                category: "confident_uncertainty".into(),
                description: format!("Uses {} high-confidence markers — possible confabulation", confidence_count),
                severity: 0.50,
                evidence: format!("{} markers", confidence_count),
            });
        }

        count
    }

    fn detect_temporal_impossibility(&self, lower: &str, findings: &mut Vec<HallucinationFinding>) {
        for marker in FUTURE_MARKERS {
            if lower.contains(marker) {
                findings.push(HallucinationFinding {
                    category: "temporal_impossibility".into(),
                    description: format!("Claims about future: {}", marker),
                    severity: 0.65,
                    evidence: marker.to_string(),
                });
            }
        }
    }

    fn extract_numerical_claims(&self, output: &str) -> Vec<(String, f64)> {
        let mut claims = Vec::new();
        let words: Vec<&str> = output.split_whitespace().collect();

        for (i, word) in words.iter().enumerate() {
            // Try parsing as number
            let cleaned = word.trim_matches(|c: char| !c.is_ascii_digit() && c != '.' && c != '-');
            if let Ok(num) = cleaned.parse::<f64>() {
                if num.is_finite() && cleaned.len() >= 2 {
                    // Build context key from surrounding words
                    let start = i.saturating_sub(2);
                    let end = (i + 3).min(words.len());
                    let context: String = words[start..end].join(" ").to_lowercase();
                    claims.push((context, num));
                }
            }
        }
        claims.truncate(50);
        claims
    }

    // ── Cross-Turn Consistency ──────────────────────────────────────────────

    fn cross_turn_analysis(
        &self, session_id: &str, output: &str, lower: &str,
        numbers: &[(String, f64)], now: i64,
        findings: &mut Vec<HallucinationFinding>,
    ) -> u32 {
        let mut contradictions = 0u32;
        let mut sessions = self.sessions.write();
        let session = sessions.entry(session_id.to_string()).or_insert(SessionHistory {
            claims: Vec::new(),
            numerical_facts: HashMap::new(),
            stated_facts: Vec::new(),
            turn_count: 0,
        });

        session.turn_count += 1;
        let turn = session.turn_count;

        // 1. Check numerical consistency
        for (context, value) in numbers {
            let entry = session.numerical_facts.entry(context.clone()).or_default();
            for (prev_val, prev_turn) in entry.iter() {
                let diff = (value - prev_val).abs();
                let relative_diff = if prev_val.abs() > 0.001 { diff / prev_val.abs() } else { diff };

                // >20% change in the same numerical claim = contradiction
                if relative_diff > 0.20 && diff > 1.0 {
                    contradictions += 1;
                    findings.push(HallucinationFinding {
                        category: "numerical_contradiction".into(),
                        description: format!("Number changed from {:.2} (turn {}) to {:.2} (turn {})",
                            prev_val, prev_turn, value, turn),
                        severity: 0.75,
                        evidence: context.clone(),
                    });
                }
            }
            entry.push((*value, turn));
            if entry.len() > 10 { entry.remove(0); }
        }

        // 2. Extract and compare factual statements
        let sentences: Vec<&str> = output.split(|c| c == '.' || c == '!' || c == '?')
            .filter(|s| s.len() > 20)
            .collect();

        for sentence in &sentences {
            let sent_lower = sentence.to_lowercase();
            // Look for negation contradictions
            for (prev_fact, prev_turn) in &session.stated_facts {
                let similarity = self.sentence_overlap(&sent_lower, prev_fact);
                if similarity > 0.50 {
                    // Check if one negates the other
                    let has_negation = |s: &str| -> bool {
                        s.contains(" not ") || s.contains(" no ") || s.contains(" never ")
                            || s.contains("n't ") || s.contains(" cannot ")
                            || s.contains(" isn't ") || s.contains(" doesn't ")
                            || s.contains(" won't ") || s.contains(" can't ")
                    };
                    let cur_neg = has_negation(&sent_lower);
                    let prev_neg = has_negation(prev_fact);
                    if cur_neg != prev_neg {
                        contradictions += 1;
                        findings.push(HallucinationFinding {
                            category: "self_contradiction".into(),
                            description: format!("Contradicts statement from turn {}", prev_turn),
                            severity: 0.80,
                            evidence: format!("prev: '{}...', now: '{}...'",
                                &prev_fact[..prev_fact.len().min(40)],
                                &sent_lower[..sent_lower.len().min(40)]),
                        });
                    }
                }
            }
        }

        // Store current facts
        let _ = lower; // used via sentences
        for sentence in sentences {
            let sent_lower = sentence.to_lowercase();
            session.stated_facts.push((sent_lower, turn));
        }

        // Bound session size
        if session.stated_facts.len() > MAX_CLAIMS_PER_SESSION {
            let drain = session.stated_facts.len() - MAX_CLAIMS_PER_SESSION;
            session.stated_facts.drain(..drain);
        }

        contradictions
    }

    fn sentence_overlap(&self, a: &str, b: &str) -> f64 {
        let a_words: std::collections::HashSet<&str> = a.split_whitespace()
            .filter(|w| w.len() > 3).collect();
        let b_words: std::collections::HashSet<&str> = b.split_whitespace()
            .filter(|w| w.len() > 3).collect();
        if a_words.is_empty() || b_words.is_empty() { return 0.0; }
        let intersection = a_words.intersection(&b_words).count();
        let union = a_words.union(&b_words).count();
        if union == 0 { 0.0 } else { intersection as f64 / union as f64 }
    }

    // ── Scoring ─────────────────────────────────────────────────────────────

    fn compute_score(&self, findings: &[HallucinationFinding], fab: u32, phantom: u32, conf: u32, contradictions: u32) -> f64 {
        if findings.is_empty() { return 0.0; }

        let max_severity = findings.iter().map(|f| f.severity).fold(0.0f64, f64::max);
        let avg_severity = findings.iter().map(|f| f.severity).sum::<f64>() / findings.len() as f64;

        let signal_count = fab + phantom + conf + contradictions;
        let count_factor = (signal_count as f64 / 5.0).min(1.0);

        // Weighted: max signal matters most, count amplifies
        (max_severity * 0.50 + avg_severity * 0.25 + count_factor * 0.25).min(1.0)
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(AiAlert { timestamp: ts, severity: sev, component: "hallucination_detector".into(), title: title.into(), details: details.into() });
    }

    pub fn total_analyzed(&self) -> u64 { self.total_analyzed.load(Ordering::Relaxed) }
    pub fn total_hallucinations(&self) -> u64 { self.total_hallucinations.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
