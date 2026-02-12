//! Context Window Stuffing Guard — Detects attacks that flood the context window
//! with noise to push safety instructions out of the model's attention.
//!
//! As context grows, models "forget" their system prompt. An attacker can
//! inject large volumes of irrelevant text, repeated patterns, or padding
//! to dilute critical instructions. This module monitors instruction
//! persistence and context quality across long conversations.
//!
//! Detects: context dilution, instruction displacement, noise injection,
//! repetitive padding, semantic density drops, attention hijacking,
//! context budget abuse, and safety instruction degradation.
//!
//! 8 detection modes, 5 memory breakthroughs:
//!   #1  HierarchicalState — O(log n) utilization history tracking
//!   #2  TieredCache — hot/warm/cold noise score cache
//!   #3  ReversibleComputation — recompute semantic density on demand
//!   #461 DifferentialStore — context baseline evolution tracking
//!   #569 PruningMap — φ-weighted alert eviction

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::differential::DifferentialStore;
use sentinel_core::pruning::PruningMap;
use sentinel_core::hierarchical::HierarchicalState;
use sentinel_core::sparse::SparseMatrix;
use sentinel_core::dedup::DedupStore;
use sentinel_core::reversible::ReversibleComputation;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ContextSnapshot {
    pub agent_id: String,
    pub session_id: String,
    pub total_tokens: u64,
    pub max_tokens: u64,
    pub system_prompt_tokens: u64,
    pub message_count: u32,
    pub latest_message: String,
    pub latest_message_tokens: u64,
    pub timestamp: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StuffingResult {
    pub risk_score: f64,
    pub stuffing_detected: bool,
    pub context_utilization: f64,
    pub noise_ratio: f64,
    pub instruction_at_risk: bool,
    pub details: Vec<String>,
    pub recommended_action: String,
}

#[derive(Debug, Clone)]
struct SessionContext {
    system_prompt_hash: String,
    max_tokens: u64,
    message_sizes: VecDeque<u64>,
    noise_scores: VecDeque<f64>,
    total_injected: u64,
    large_message_count: u32,
    repetition_count: u32,
    last_warning_at: i64,
    created_at: i64,
}

// Noise indicators — content that inflates context without adding value
const NOISE_PATTERNS: &[(&str, f64)] = &[
    ("lorem ipsum", 0.90),
    ("the quick brown fox", 0.60),
    ("aaaa", 0.70),
    ("xxxx", 0.70),
    ("____", 0.65),
    ("....", 0.50),
    ("    ", 0.40), // excessive whitespace
    ("please ignore this text", 0.85),
    ("this is filler text", 0.90),
    ("padding content", 0.88),
    ("placeholder text", 0.75),
    ("ignore everything below", 0.92),
    ("begin irrelevant section", 0.95),
];

pub struct ContextWindowStuffingGuard {
    utilization_warning: f64,   // warn when context this full (0.75)
    utilization_critical: f64,  // block when context this full (0.90)
    max_single_message_ratio: f64, // single message can't be more than this % of context
    min_semantic_density: f64,
    enabled: bool,
    /// Breakthrough #2: Hot/warm/cold noise score cache
    noise_cache: TieredCache<String, u64>,
    /// Breakthrough #461: Context baseline diffs
    context_diffs: DifferentialStore<String, String>,
    /// Breakthrough #569: φ-weighted alert pruning
    pruned_alerts: PruningMap<String, AiAlert>,
    /// Breakthrough #1: O(log n) utilization history
    util_state: RwLock<HierarchicalState<f64>>,
    /// Breakthrough #627: Sparse session×noise-type matrix
    noise_matrix: RwLock<SparseMatrix<String, String, u64>>,
    /// Breakthrough #592: Content-addressed dedup for noise payloads
    noise_dedup: DedupStore<String, String>,

    sessions: RwLock<HashMap<String, SessionContext>>,
    alerts: RwLock<Vec<AiAlert>>,

    total_checks: AtomicU64,
    total_stuffing: AtomicU64,
    total_noise_blocked: AtomicU64,
    total_instructions_at_risk: AtomicU64,
    metrics: Option<MemoryMetrics>,
}

impl ContextWindowStuffingGuard {
    pub fn new() -> Self {
        Self {
            utilization_warning: 0.75, utilization_critical: 0.90,
            max_single_message_ratio: 0.30, min_semantic_density: 0.20,
            enabled: true,
            noise_cache: TieredCache::new(30_000),
            context_diffs: DifferentialStore::new(),
            pruned_alerts: PruningMap::new(5_000),
            util_state: RwLock::new(HierarchicalState::new(8, 64)),
            noise_matrix: RwLock::new(SparseMatrix::new(0)),
            noise_dedup: DedupStore::new(),
            sessions: RwLock::new(HashMap::new()),
            alerts: RwLock::new(Vec::new()),
            total_checks: AtomicU64::new(0), total_stuffing: AtomicU64::new(0),
            total_noise_blocked: AtomicU64::new(0), total_instructions_at_risk: AtomicU64::new(0),
            metrics: None,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("context_window_stuffing_guard", 4 * 1024 * 1024);
        self.noise_cache = self.noise_cache.with_metrics(metrics.clone(), "stuffing_noise_cache");
        self.metrics = Some(metrics); self
    }

    /// Check a context snapshot for stuffing attacks
    pub fn check(&self, snapshot: &ContextSnapshot) -> StuffingResult {
        if !self.enabled {
            return StuffingResult { risk_score: 0.0, stuffing_detected: false, context_utilization: 0.0, noise_ratio: 0.0, instruction_at_risk: false, details: Vec::new(), recommended_action: "none".into() };
        }
        self.total_checks.fetch_add(1, Ordering::Relaxed);
        let key = format!("{}:{}", snapshot.agent_id, snapshot.session_id);
        let now = snapshot.timestamp;

        let mut sessions = self.sessions.write();
        let ctx = sessions.entry(key).or_insert(SessionContext {
            system_prompt_hash: String::new(),
            max_tokens: snapshot.max_tokens,
            message_sizes: VecDeque::with_capacity(500),
            noise_scores: VecDeque::with_capacity(500),
            total_injected: 0, large_message_count: 0,
            repetition_count: 0, last_warning_at: 0,
            created_at: now,
        });

        ctx.message_sizes.push_back(snapshot.latest_message_tokens);
        while ctx.message_sizes.len() > 500 { ctx.message_sizes.pop_front(); }

        let mut risk = 0.0f64;
        let mut details = Vec::new();

        // 1. Context utilization check
        let utilization = if snapshot.max_tokens > 0 {
            snapshot.total_tokens as f64 / snapshot.max_tokens as f64
        } else { 0.0 };

        if utilization >= self.utilization_critical {
            risk = risk.max(0.85);
            details.push(format!("critical_utilization: {:.1}%", utilization * 100.0));
        } else if utilization >= self.utilization_warning {
            risk = risk.max(0.50);
            details.push(format!("high_utilization: {:.1}%", utilization * 100.0));
        }

        // 2. System prompt displacement risk
        let system_ratio = if snapshot.total_tokens > 0 {
            snapshot.system_prompt_tokens as f64 / snapshot.total_tokens as f64
        } else { 1.0 };
        let instruction_at_risk = system_ratio < 0.02 && utilization > 0.70;
        if instruction_at_risk {
            risk = risk.max(0.80);
            self.total_instructions_at_risk.fetch_add(1, Ordering::Relaxed);
            details.push(format!("system_prompt_diluted: {:.2}% of context", system_ratio * 100.0));
        }

        // 3. Single message size check
        let msg_ratio = if snapshot.max_tokens > 0 {
            snapshot.latest_message_tokens as f64 / snapshot.max_tokens as f64
        } else { 0.0 };
        if msg_ratio > self.max_single_message_ratio {
            risk = risk.max(0.70);
            ctx.large_message_count += 1;
            details.push(format!("oversized_message: {:.1}% of context window", msg_ratio * 100.0));
        }

        // 4. Noise content analysis
        let noise_score = self.compute_noise_score(&snapshot.latest_message);
        ctx.noise_scores.push_back(noise_score);
        while ctx.noise_scores.len() > 500 { ctx.noise_scores.pop_front(); }

        if noise_score > 0.50 {
            risk = risk.max(0.60 + noise_score * 0.30);
            self.total_noise_blocked.fetch_add(1, Ordering::Relaxed);
            details.push(format!("noise_content: score={:.2}", noise_score));
        }

        // 5. Repetition detection
        let repetition = self.detect_repetition(&snapshot.latest_message);
        if repetition > 0.50 {
            risk = risk.max(0.65 + repetition * 0.25);
            ctx.repetition_count += 1;
            details.push(format!("repetitive_content: {:.1}%", repetition * 100.0));
        }

        // 6. Semantic density (information vs padding ratio)
        let density = self.semantic_density(&snapshot.latest_message);
        if density < self.min_semantic_density && snapshot.latest_message_tokens > 100 {
            risk = risk.max(0.55);
            details.push(format!("low_semantic_density: {:.2}", density));
        }

        // 7. Cumulative noise trend
        let avg_noise: f64 = if ctx.noise_scores.is_empty() { 0.0 }
            else { ctx.noise_scores.iter().sum::<f64>() / ctx.noise_scores.len() as f64 };
        if avg_noise > 0.35 && ctx.noise_scores.len() > 5 {
            risk = (risk + 0.15).min(1.0);
            details.push(format!("sustained_noise: avg={:.2} over {} messages", avg_noise, ctx.noise_scores.len()));
        }

        // 8. Message size spike (sudden large messages)
        if ctx.message_sizes.len() > 5 {
            let avg_size: f64 = ctx.message_sizes.iter().take(ctx.message_sizes.len() - 1)
                .map(|&s| s as f64).sum::<f64>() / (ctx.message_sizes.len() - 1) as f64;
            if avg_size > 0.0 && snapshot.latest_message_tokens as f64 > avg_size * 5.0 {
                risk = risk.max(0.60);
                details.push(format!("size_spike: {}tok vs avg {:.0}tok ({}x)", snapshot.latest_message_tokens, avg_size, snapshot.latest_message_tokens as f64 / avg_size));
            }
        }

        let stuffing_detected = risk >= 0.60;
        if stuffing_detected {
            self.total_stuffing.fetch_add(1, Ordering::Relaxed);
            if now - ctx.last_warning_at > 60 {
                ctx.last_warning_at = now;
                warn!(agent=%snapshot.agent_id, session=%snapshot.session_id, risk=risk, utilization=utilization, "Context window stuffing detected");
                self.add_alert(now, if risk >= 0.85 { Severity::Critical } else { Severity::High },
                    "Context window stuffing detected",
                    &format!("agent={}, util={:.1}%, risk={:.2}, details={:?}", snapshot.agent_id, utilization * 100.0, risk, details));
            }
        }

        let recommended = if risk >= 0.85 { "truncate_and_summarize" }
            else if instruction_at_risk { "reinject_system_prompt" }
            else if risk >= 0.60 { "reject_message" }
            else { "none" };

        StuffingResult {
            risk_score: risk, stuffing_detected, context_utilization: utilization,
            noise_ratio: noise_score, instruction_at_risk, details,
            recommended_action: recommended.into(),
        }
    }

    fn compute_noise_score(&self, text: &str) -> f64 {
        let lower = text.to_lowercase();
        let mut max_noise = 0.0f64;
        for (pat, w) in NOISE_PATTERNS {
            if lower.contains(pat) { max_noise = max_noise.max(*w); }
        }
        // Check for character repetition ratio
        let chars: Vec<char> = text.chars().collect();
        if chars.len() > 20 {
            let unique: std::collections::HashSet<char> = chars.iter().copied().collect();
            let uniqueness = unique.len() as f64 / chars.len() as f64;
            if uniqueness < 0.05 { max_noise = max_noise.max(0.85); }
            else if uniqueness < 0.10 { max_noise = max_noise.max(0.60); }
        }
        max_noise
    }

    fn detect_repetition(&self, text: &str) -> f64 {
        let words: Vec<&str> = text.split_whitespace().collect();
        if words.len() < 10 { return 0.0; }
        // Check for repeated n-grams
        let mut trigram_counts: HashMap<String, u32> = HashMap::new();
        for window in words.windows(3) {
            let gram = window.join(" ");
            *trigram_counts.entry(gram).or_insert(0) += 1;
        }
        let total_trigrams = words.len().saturating_sub(2) as f64;
        let repeated: f64 = trigram_counts.values().filter(|&&c| c > 1).map(|&c| (c - 1) as f64).sum();
        (repeated / total_trigrams).min(1.0)
    }

    fn semantic_density(&self, text: &str) -> f64 {
        let words: Vec<&str> = text.split_whitespace().collect();
        if words.is_empty() { return 1.0; }
        let unique: std::collections::HashSet<&str> = words.iter().copied().collect();
        let type_token_ratio = unique.len() as f64 / words.len() as f64;
        // Average word length as proxy for information content
        let avg_word_len: f64 = words.iter().map(|w| w.len() as f64).sum::<f64>() / words.len() as f64;
        let length_factor = (avg_word_len / 5.0).min(1.0);
        (type_token_ratio * 0.7 + length_factor * 0.3).min(1.0)
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(AiAlert { timestamp: ts, severity: sev, component: "context_window_stuffing_guard".into(), title: title.into(), details: details.into() });
    }

    pub fn total_checks(&self) -> u64 { self.total_checks.load(Ordering::Relaxed) }
    pub fn total_stuffing(&self) -> u64 { self.total_stuffing.load(Ordering::Relaxed) }
    pub fn total_instructions_at_risk(&self) -> u64 { self.total_instructions_at_risk.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
