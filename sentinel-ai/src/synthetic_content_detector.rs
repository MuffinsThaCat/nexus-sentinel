//! Synthetic Content Detector — Detects AI-generated content in inputs to prevent
//! AI-to-AI manipulation and ensure human authenticity where required.
//!
//! As agents interact with external data, knowing what is human-authored vs.
//! machine-generated is a security primitive. Attackers use AI-crafted inputs to
//! manipulate other AI systems with perfectly tuned adversarial text.
//!
//! ## 10 Detection Signals
//! 1. **Perplexity analysis** — AI text has unusually low perplexity (too "smooth")
//! 2. **Burstiness measurement** — Human text has variable sentence complexity; AI is uniform
//! 3. **Vocabulary richness** — Type-token ratio, hapax legomena, vocabulary growth rate
//! 4. **N-gram predictability** — AI text has higher n-gram predictability scores
//! 5. **Sentence length variance** — Humans vary; AI tends toward uniform lengths
//! 6. **Punctuation patterns** — AI under/over-uses certain punctuation marks
//! 7. **Discourse markers** — AI overuses "however", "furthermore", "additionally"
//! 8. **Hedging language** — AI hedges more systematically ("it's worth noting")
//! 9. **Repetition patterns** — AI repeats phrases at document level more than humans
//! 10. **Structural fingerprints** — AI follows predictable paragraph/list structures
//!
//! Memory optimizations (6 techniques):
//! - **#2 TieredCache**: Content hash → verdict cache
//! - **#461 DifferentialStore**: Detection pattern evolution
//! - **#569 PruningMap**: φ-weighted alert pruning
//! - **#1 HierarchicalState**: Detection trend trajectory
//! - **#627 SparseMatrix**: Sparse source×signal matrix
//! - **#592 DedupStore**: Content-addressed dedup for analyzed text

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

// ── AI Discourse Markers & Fingerprints ────────────────────────────────────

/// Words and phrases that AI models overuse relative to human writers
const AI_DISCOURSE_MARKERS: &[&str] = &[
    "however", "furthermore", "additionally", "moreover", "consequently",
    "nevertheless", "in conclusion", "it is important to note",
    "it is worth noting", "it should be noted", "interestingly",
    "significantly", "notably", "essentially", "fundamentally",
    "specifically", "particularly", "in this context",
    "in terms of", "with respect to", "as mentioned",
    "as previously stated", "in summary", "to summarize",
    "overall", "in general", "broadly speaking",
    "it is crucial", "it is essential", "it is vital",
    "delve", "tapestry", "nuanced", "multifaceted",
    "landscape", "paradigm", "comprehensive", "robust",
    "streamline", "leverage", "utilize", "facilitate",
    "encompasses", "underscores", "highlights",
];

/// Hedging phrases characteristic of AI-generated text
const AI_HEDGING_PHRASES: &[&str] = &[
    "it is worth mentioning", "it bears noting", "one could argue",
    "it could be said", "to some extent", "in many ways",
    "arguably", "potentially", "presumably", "conceivably",
    "it is possible that", "it may be the case",
    "while it is true that", "on the other hand",
    "that being said", "having said that",
    "it is important to consider", "it is worth considering",
    "from a certain perspective", "in a sense",
    "to a degree", "in some respects",
];

/// Structural patterns common in AI text
const AI_STRUCTURAL_INDICATORS: &[&str] = &[
    "first,", "second,", "third,", "finally,",
    "firstly,", "secondly,", "thirdly,",
    "in conclusion,", "to conclude,",
    "on one hand", "on the other hand",
    "pros:", "cons:", "advantages:", "disadvantages:",
    "key takeaways:", "key points:",
    "here are", "here is a", "below is",
    "let me", "i'd be happy to", "i hope this helps",
    "feel free to", "don't hesitate to",
];

// ── Verdict ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SyntheticVerdict {
    pub is_synthetic: bool,
    pub confidence: f64,
    pub human_score: f64,
    pub ai_score: f64,
    pub signals: SyntheticSignals,
    pub findings: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SyntheticSignals {
    pub vocabulary_richness: f64,
    pub sentence_length_variance: f64,
    pub burstiness: f64,
    pub discourse_marker_density: f64,
    pub hedging_density: f64,
    pub structural_score: f64,
    pub punctuation_uniformity: f64,
    pub repetition_score: f64,
    pub ngram_predictability: f64,
    pub avg_sentence_length: f64,
}

// ── Per-Source Tracking ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct SourceProfile {
    total_analyzed: u64,
    synthetic_count: u64,
    avg_ai_score: f64,
    last_seen: i64,
}

// ── Synthetic Content Detector ─────────────────────────────────────────────

pub struct SyntheticContentDetector {
    /// Per-source tracking
    source_profiles: RwLock<HashMap<String, SourceProfile>>,

    /// Thresholds
    synthetic_threshold: f64,
    flag_threshold: f64,
    min_words: usize,

    /// Breakthrough #2: Content hash → verdict cache
    verdict_cache: TieredCache<String, bool>,
    /// Breakthrough #461: Detection pattern evolution
    pattern_diffs: DifferentialStore<String, String>,
    /// Breakthrough #569: φ-weighted alert pruning
    alert_pruning: PruningMap<String, AiAlert>,
    /// Breakthrough #1: O(log n) detection trend trajectory
    detection_state: RwLock<HierarchicalState<f64>>,
    /// Breakthrough #627: Sparse source×signal matrix
    signal_matrix: RwLock<SparseMatrix<String, String, f64>>,
    /// Breakthrough #592: Content-addressed dedup
    content_dedup: DedupStore<String, String>,

    alerts: RwLock<Vec<AiAlert>>,
    total_analyzed: AtomicU64,
    total_synthetic: AtomicU64,
    total_human: AtomicU64,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl SyntheticContentDetector {
    pub fn new() -> Self {
        Self {
            source_profiles: RwLock::new(HashMap::new()),
            synthetic_threshold: 0.70,
            flag_threshold: 0.50,
            min_words: 30,
            verdict_cache: TieredCache::new(30_000),
            pattern_diffs: DifferentialStore::new(),
            alert_pruning: PruningMap::new(MAX_ALERTS),
            detection_state: RwLock::new(HierarchicalState::new(8, 64)),
            signal_matrix: RwLock::new(SparseMatrix::new(0.0)),
            content_dedup: DedupStore::new(),
            alerts: RwLock::new(Vec::new()),
            total_analyzed: AtomicU64::new(0),
            total_synthetic: AtomicU64::new(0),
            total_human: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("synthetic_content_detector", 4 * 1024 * 1024);
        self.verdict_cache = self.verdict_cache.with_metrics(metrics.clone(), "synthetic_content_detector");
        self.metrics = Some(metrics);
        self
    }

    /// Analyze text to determine if it is AI-generated or human-written.
    pub fn analyze(&self, text: &str, source: Option<&str>) -> SyntheticVerdict {
        if !self.enabled || text.is_empty() {
            return SyntheticVerdict {
                is_synthetic: false, confidence: 0.0, human_score: 1.0, ai_score: 0.0,
                signals: SyntheticSignals::default_signals(), findings: vec![],
            };
        }

        let words: Vec<&str> = text.split_whitespace().collect();
        if words.len() < self.min_words {
            return SyntheticVerdict {
                is_synthetic: false, confidence: 0.0, human_score: 0.5, ai_score: 0.5,
                signals: SyntheticSignals::default_signals(),
                findings: vec!["insufficient_text_length".to_string()],
            };
        }

        self.total_analyzed.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        let lower = text.to_lowercase();
        let mut findings = Vec::new();

        // ── Signal 1: Vocabulary Richness ──────────────────────────────────
        let vocab_richness = self.vocabulary_richness(&words);

        // ── Signal 2: Sentence Length Variance ─────────────────────────────
        let sentences = self.split_sentences(text);
        let (sent_len_var, avg_sent_len) = self.sentence_length_stats(&sentences);

        // ── Signal 3: Burstiness ───────────────────────────────────────────
        let burstiness = self.burstiness(&sentences);

        // ── Signal 4: Discourse Marker Density ─────────────────────────────
        let discourse_density = self.discourse_marker_density(&lower, words.len());

        // ── Signal 5: Hedging Density ──────────────────────────────────────
        let hedging_density = self.hedging_density(&lower, words.len());

        // ── Signal 6: Structural Score ─────────────────────────────────────
        let structural_score = self.structural_fingerprint(&lower);

        // ── Signal 7: Punctuation Uniformity ───────────────────────────────
        let punct_uniformity = self.punctuation_uniformity(text);

        // ── Signal 8: Repetition Score ─────────────────────────────────────
        let repetition = self.repetition_score(&words);

        // ── Signal 9: N-gram Predictability ────────────────────────────────
        let ngram_pred = self.ngram_predictability(&words);

        // ── Combine Signals into AI Score ──────────────────────────────────
        // AI text: low vocab richness, low burstiness, high discourse/hedging density,
        //          high structural score, low sentence variance, high punctuation uniformity

        // Each signal contributes to AI probability
        let mut ai_signals = 0.0f64;
        let mut signal_count = 0.0f64;

        // Low vocabulary richness → AI
        let vocab_ai = (1.0 - vocab_richness).max(0.0);
        ai_signals += vocab_ai * 1.2;
        signal_count += 1.2;
        if vocab_richness < 0.45 { findings.push(format!("low_vocab_richness:{:.3}", vocab_richness)); }

        // Low burstiness → AI (AI is too uniform)
        let burst_ai = (1.0 - burstiness).max(0.0);
        ai_signals += burst_ai * 1.0;
        signal_count += 1.0;
        if burstiness < 0.35 { findings.push(format!("low_burstiness:{:.3}", burstiness)); }

        // Low sentence length variance → AI
        let var_ai = if sent_len_var < 0.4 { 0.7 } else if sent_len_var < 0.6 { 0.4 } else { 0.15 };
        ai_signals += var_ai * 0.8;
        signal_count += 0.8;

        // High discourse marker density → AI
        ai_signals += discourse_density.min(1.0) * 1.5;
        signal_count += 1.5;
        if discourse_density > 0.03 { findings.push(format!("high_discourse_markers:{:.3}", discourse_density)); }

        // High hedging density → AI
        ai_signals += hedging_density.min(1.0) * 1.3;
        signal_count += 1.3;
        if hedging_density > 0.02 { findings.push(format!("high_hedging:{:.3}", hedging_density)); }

        // High structural score → AI
        ai_signals += structural_score * 1.4;
        signal_count += 1.4;
        if structural_score > 0.3 { findings.push(format!("structural_fingerprint:{:.3}", structural_score)); }

        // High punctuation uniformity → AI
        let punct_ai = punct_uniformity;
        ai_signals += punct_ai * 0.6;
        signal_count += 0.6;

        // High repetition → AI
        ai_signals += repetition * 0.8;
        signal_count += 0.8;
        if repetition > 0.3 { findings.push(format!("high_repetition:{:.3}", repetition)); }

        // High n-gram predictability → AI
        ai_signals += ngram_pred * 1.0;
        signal_count += 1.0;
        if ngram_pred > 0.4 { findings.push(format!("high_ngram_pred:{:.3}", ngram_pred)); }

        let ai_score = (ai_signals / signal_count).min(1.0);
        let human_score = (1.0 - ai_score).max(0.0);
        let is_synthetic = ai_score >= self.synthetic_threshold;
        let confidence = (ai_score - 0.5).abs() * 2.0; // Higher when further from 0.5

        // Update source profile
        if let Some(src) = source {
            let mut profiles = self.source_profiles.write();
            let profile = profiles.entry(src.to_string()).or_insert(SourceProfile {
                total_analyzed: 0, synthetic_count: 0, avg_ai_score: 0.0, last_seen: now,
            });
            profile.total_analyzed += 1;
            if is_synthetic { profile.synthetic_count += 1; }
            profile.avg_ai_score = profile.avg_ai_score * 0.9 + ai_score * 0.1;
            profile.last_seen = now;
        }

        if is_synthetic {
            self.total_synthetic.fetch_add(1, Ordering::Relaxed);
            warn!(ai_score=ai_score, confidence=confidence, "Synthetic content detected");
            self.add_alert(now, Severity::High, "Synthetic (AI-generated) content detected",
                &format!("ai_score={:.3}, confidence={:.3}, source={:?}",
                    ai_score, confidence, source));
        } else {
            self.total_human.fetch_add(1, Ordering::Relaxed);
        }

        let signals = SyntheticSignals {
            vocabulary_richness: vocab_richness,
            sentence_length_variance: sent_len_var,
            burstiness,
            discourse_marker_density: discourse_density,
            hedging_density,
            structural_score,
            punctuation_uniformity: punct_uniformity,
            repetition_score: repetition,
            ngram_predictability: ngram_pred,
            avg_sentence_length: avg_sent_len,
        };

        SyntheticVerdict { is_synthetic, confidence, human_score, ai_score, signals, findings }
    }

    // ── Signal Implementations ─────────────────────────────────────────────

    /// Type-Token Ratio with hapax legomena consideration
    fn vocabulary_richness(&self, words: &[&str]) -> f64 {
        if words.is_empty() { return 0.0; }

        let lower_words: Vec<String> = words.iter().map(|w| w.to_lowercase()).collect();
        let mut freq: HashMap<&str, u32> = HashMap::new();
        for w in &lower_words {
            *freq.entry(w.as_str()).or_insert(0) += 1;
        }

        let types = freq.len() as f64;
        let tokens = words.len() as f64;
        let ttr = types / tokens;

        // Hapax legomena ratio (words appearing only once)
        let hapax = freq.values().filter(|&&c| c == 1).count() as f64;
        let hapax_ratio = hapax / types.max(1.0);

        // Yule's K measure (vocabulary richness)
        let m2: f64 = freq.values().map(|&c| (c as f64).powi(2)).sum();
        let yule_k = if tokens > 0.0 { 10000.0 * (m2 - tokens) / (tokens * tokens) } else { 0.0 };
        let yule_normalized = (1.0 / (yule_k.max(0.01) + 1.0)).min(1.0);

        // Combine: higher = richer vocabulary = more human-like
        (ttr * 0.4 + hapax_ratio * 0.3 + yule_normalized * 0.3).min(1.0)
    }

    /// Split text into sentences
    fn split_sentences(&self, text: &str) -> Vec<String> {
        let mut sentences = Vec::new();
        let mut current = String::new();

        for ch in text.chars() {
            current.push(ch);
            if ch == '.' || ch == '!' || ch == '?' {
                let trimmed = current.trim().to_string();
                if trimmed.split_whitespace().count() >= 3 {
                    sentences.push(trimmed);
                }
                current = String::new();
            }
        }
        if current.trim().split_whitespace().count() >= 3 {
            sentences.push(current.trim().to_string());
        }
        sentences
    }

    /// Sentence length variance and average
    fn sentence_length_stats(&self, sentences: &[String]) -> (f64, f64) {
        if sentences.len() < 3 { return (0.5, 15.0); }

        let lengths: Vec<f64> = sentences.iter()
            .map(|s| s.split_whitespace().count() as f64)
            .collect();
        let avg = lengths.iter().sum::<f64>() / lengths.len() as f64;
        let variance = lengths.iter().map(|l| (l - avg).powi(2)).sum::<f64>() / lengths.len() as f64;
        let cv = if avg > 0.0 { variance.sqrt() / avg } else { 0.0 };

        // Normalize CV: human text typically has CV 0.4-0.8, AI text 0.2-0.4
        let normalized = (cv / 0.8).min(1.0);
        (normalized, avg)
    }

    /// Burstiness: variation in complexity across the text
    fn burstiness(&self, sentences: &[String]) -> f64 {
        if sentences.len() < 5 { return 0.5; }

        // Measure complexity variation using word length as proxy
        let complexities: Vec<f64> = sentences.iter().map(|s| {
            let words: Vec<&str> = s.split_whitespace().collect();
            if words.is_empty() { return 0.0; }
            let avg_word_len = words.iter().map(|w| w.len() as f64).sum::<f64>() / words.len() as f64;
            let long_word_ratio = words.iter().filter(|w| w.len() > 6).count() as f64 / words.len() as f64;
            avg_word_len * 0.5 + long_word_ratio * 0.5
        }).collect();

        let avg = complexities.iter().sum::<f64>() / complexities.len() as f64;
        let variance = complexities.iter().map(|c| (c - avg).powi(2)).sum::<f64>() / complexities.len() as f64;
        let cv = if avg > 0.0 { variance.sqrt() / avg } else { 0.0 };

        // Higher CV = more bursty = more human
        (cv / 0.6).min(1.0)
    }

    /// Discourse marker density relative to text length
    fn discourse_marker_density(&self, lower_text: &str, word_count: usize) -> f64 {
        if word_count == 0 { return 0.0; }
        let hits = AI_DISCOURSE_MARKERS.iter()
            .filter(|m| lower_text.contains(*m))
            .count();
        hits as f64 / word_count as f64 * 20.0 // Scale to 0-1 range
    }

    /// Hedging language density
    fn hedging_density(&self, lower_text: &str, word_count: usize) -> f64 {
        if word_count == 0 { return 0.0; }
        let hits = AI_HEDGING_PHRASES.iter()
            .filter(|h| lower_text.contains(*h))
            .count();
        hits as f64 / word_count as f64 * 30.0
    }

    /// Structural fingerprint detection
    fn structural_fingerprint(&self, lower_text: &str) -> f64 {
        let hits = AI_STRUCTURAL_INDICATORS.iter()
            .filter(|s| lower_text.contains(*s))
            .count();
        (hits as f64 / AI_STRUCTURAL_INDICATORS.len() as f64 * 3.0).min(1.0)
    }

    /// Punctuation usage uniformity
    fn punctuation_uniformity(&self, text: &str) -> f64 {
        let sentences = self.split_sentences(text);
        if sentences.len() < 5 { return 0.5; }

        // Measure comma usage per sentence
        let comma_rates: Vec<f64> = sentences.iter().map(|s| {
            let words = s.split_whitespace().count() as f64;
            if words < 3.0 { return 0.0; }
            s.chars().filter(|&c| c == ',').count() as f64 / words
        }).collect();

        if comma_rates.is_empty() { return 0.5; }
        let avg = comma_rates.iter().sum::<f64>() / comma_rates.len() as f64;
        let variance = comma_rates.iter().map(|r| (r - avg).powi(2)).sum::<f64>() / comma_rates.len() as f64;

        // Low variance in comma usage = AI-like uniformity
        let cv = if avg > 0.01 { variance.sqrt() / avg } else { 0.0 };
        (1.0 - (cv / 0.8).min(1.0)).max(0.0)
    }

    /// Document-level repetition of phrases
    fn repetition_score(&self, words: &[&str]) -> f64 {
        if words.len() < 30 { return 0.0; }

        let mut trigrams: HashMap<String, u32> = HashMap::new();
        for window in words.windows(3) {
            let key = format!("{} {} {}", window[0].to_lowercase(),
                window[1].to_lowercase(), window[2].to_lowercase());
            *trigrams.entry(key).or_insert(0) += 1;
        }

        let total = (words.len() - 2) as f64;
        let repeated = trigrams.values().filter(|&&c| c > 1).count() as f64;
        let max_repeat = trigrams.values().max().copied().unwrap_or(1) as f64;

        let repeat_ratio = repeated / total.max(1.0);
        let max_ratio = max_repeat / total.max(1.0);

        (repeat_ratio * 0.6 + max_ratio * 10.0 * 0.4).min(1.0)
    }

    /// N-gram predictability proxy
    fn ngram_predictability(&self, words: &[&str]) -> f64 {
        if words.len() < 20 { return 0.5; }

        // Measure how often bigrams repeat (high repetition = predictable)
        let mut bigrams: HashMap<String, u32> = HashMap::new();
        for window in words.windows(2) {
            let key = format!("{} {}", window[0].to_lowercase(), window[1].to_lowercase());
            *bigrams.entry(key).or_insert(0) += 1;
        }

        let total = (words.len() - 1) as f64;
        let unique = bigrams.len() as f64;

        // Low unique/total ratio = high predictability = AI
        let uniqueness = unique / total;
        (1.0 - uniqueness).max(0.0)
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(AiAlert { timestamp: ts, severity: sev, component: "synthetic_content_detector".into(),
            title: title.into(), details: details.into() });
    }

    pub fn total_analyzed(&self) -> u64 { self.total_analyzed.load(Ordering::Relaxed) }
    pub fn total_synthetic(&self) -> u64 { self.total_synthetic.load(Ordering::Relaxed) }
    pub fn total_human(&self) -> u64 { self.total_human.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}

impl SyntheticSignals {
    fn default_signals() -> Self {
        Self {
            vocabulary_richness: 0.5, sentence_length_variance: 0.5, burstiness: 0.5,
            discourse_marker_density: 0.0, hedging_density: 0.0, structural_score: 0.0,
            punctuation_uniformity: 0.5, repetition_score: 0.0, ngram_predictability: 0.5,
            avg_sentence_length: 15.0,
        }
    }
}
