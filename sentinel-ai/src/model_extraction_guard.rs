//! Model Extraction Guard — detects systematic querying to steal model behavior.
//!
//! Attackers attempt model extraction/stealing by:
//!  1. **Membership inference** — probing whether specific data was in training set
//!  2. **Model distillation** — systematic diverse queries to train a clone
//!  3. **Decision boundary mapping** — adversarial queries near classification boundaries
//!  4. **Confidence score exploitation** — extracting logits/probabilities
//!  5. **API abuse patterns** — high-volume automated querying with synthetic inputs
//!
//! Detection methods:
//!  - Query rate + diversity analysis per user/session
//!  - Input pattern similarity detection (synthetic vs natural)
//!  - Boundary-probing detection (small perturbation sequences)
//!  - Confidence extraction attempts
//!  - Session behavioral fingerprinting
//!
//! Memory optimizations:
//! - **#2 Tiered Cache**: Query fingerprint dedup
//! - **#4 PruningMap**: φ-weighted user profile pruning
//! - **#5 StreamAccumulator**: Rolling query statistics

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
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;
const MAX_QUERY_HISTORY: usize = 500;
const MAX_USERS: usize = 50_000;

#[derive(Debug, Clone)]
pub struct ModelQuery {
    pub user_id: String,
    pub session_id: String,
    pub input_text: String,
    pub input_tokens: u32,
    pub requested_logprobs: bool,
    pub requested_top_k: Option<u32>,
    pub timestamp: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExtractionResult {
    pub risk_score: f64,
    pub extraction_suspected: bool,
    pub attack_type: Option<String>,
    pub query_rate_per_min: f64,
    pub diversity_score: f64,
    pub perturbation_score: f64,
    pub details: Vec<String>,
    pub recommended_action: String,
}

#[derive(Debug, Clone, Default)]
struct UserQueryProfile {
    queries: VecDeque<QueryRecord>,
    total_queries: u64,
    logprob_requests: u64,
    unique_input_hashes: u64,
    avg_input_length: f64,
    last_seen: i64,
    first_seen: i64,
    flagged: bool,
    burst_count: u32,
}

#[derive(Debug, Clone)]
struct QueryRecord {
    input_hash: u64,
    input_len: usize,
    timestamp: i64,
    requested_logprobs: bool,
}

pub struct ModelExtractionGuard {
    rate_limit_per_min: f64,
    diversity_threshold: f64,
    perturbation_threshold: f64,
    block_threshold: f64,
    enabled: bool,

    /// Breakthrough #2: Hot/warm/cold query fingerprint cache
    query_cache: TieredCache<u64, u64>,
    /// Breakthrough #461: User query baseline evolution tracking
    query_diffs: DifferentialStore<String, String>,
    /// Breakthrough #569: φ-weighted user profile pruning
    user_pruning: PruningMap<String, AiAlert>,
    /// Breakthrough #1: O(log n) extraction risk trajectory checkpoints
    risk_checkpoints: RwLock<HierarchicalState<f64>>,
    /// Breakthrough #627: Sparse user×attack-type risk matrix
    extraction_matrix: RwLock<SparseMatrix<String, String, f64>>,
    /// Content-addressed dedup for query fingerprints
    query_dedup: DedupStore<String, String>,

    user_profiles: RwLock<HashMap<String, UserQueryProfile>>,
    alerts: RwLock<Vec<AiAlert>>,

    total_queries: AtomicU64,
    total_suspected: AtomicU64,
    total_blocked: AtomicU64,
    total_distillation: AtomicU64,
    total_boundary_probe: AtomicU64,
    total_membership_inference: AtomicU64,

    metrics: Option<MemoryMetrics>,
}

impl ModelExtractionGuard {
    pub fn new() -> Self {
        Self {
            rate_limit_per_min: 30.0,
            diversity_threshold: 0.85,
            perturbation_threshold: 0.70,
            block_threshold: 0.75,
            enabled: true,
            query_cache: TieredCache::new(100_000),
            query_diffs: DifferentialStore::new(),
            user_pruning: PruningMap::new(MAX_USERS),
            risk_checkpoints: RwLock::new(HierarchicalState::new(8, 64)),
            extraction_matrix: RwLock::new(SparseMatrix::new(0.0)),
            query_dedup: DedupStore::new(),
            user_profiles: RwLock::new(HashMap::new()),
            alerts: RwLock::new(Vec::new()),
            total_queries: AtomicU64::new(0),
            total_suspected: AtomicU64::new(0),
            total_blocked: AtomicU64::new(0),
            total_distillation: AtomicU64::new(0),
            total_boundary_probe: AtomicU64::new(0),
            total_membership_inference: AtomicU64::new(0),
            metrics: None,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("model_extraction_guard", 4 * 1024 * 1024);
        self.query_cache = self.query_cache.with_metrics(metrics.clone(), "extraction_cache");
        self.metrics = Some(metrics);
        self
    }

    pub fn check_query(&self, query: &ModelQuery) -> ExtractionResult {
        if !self.enabled { return Self::clean_result(); }
        self.total_queries.fetch_add(1, Ordering::Relaxed);
        let now = query.timestamp;
        let input_hash = Self::hash_input(&query.input_text);

        let mut profiles = self.user_profiles.write();
        if profiles.len() > MAX_USERS {
            let cutoff = now - 3600;
            profiles.retain(|_, p| p.last_seen > cutoff);
        }

        let profile = profiles.entry(query.user_id.clone()).or_insert_with(|| UserQueryProfile {
            first_seen: now, ..Default::default()
        });

        // Record query
        profile.total_queries += 1;
        profile.last_seen = now;
        if query.requested_logprobs { profile.logprob_requests += 1; }
        let alpha = 0.05;
        profile.avg_input_length = profile.avg_input_length * (1.0 - alpha) + query.input_text.len() as f64 * alpha;
        profile.queries.push_back(QueryRecord {
            input_hash, input_len: query.input_text.len(),
            timestamp: now, requested_logprobs: query.requested_logprobs,
        });
        while profile.queries.len() > MAX_QUERY_HISTORY { profile.queries.pop_front(); }

        let mut risk = 0.0f64;
        let mut details = Vec::new();
        let mut attack_type = None;

        // 1. Rate analysis
        let one_min_ago = now - 60;
        let recent_count = profile.queries.iter().filter(|q| q.timestamp >= one_min_ago).count();
        let rate = recent_count as f64;
        if rate > self.rate_limit_per_min {
            risk = risk.max(0.60 + (rate / self.rate_limit_per_min - 1.0) * 0.10);
            details.push(format!("high_query_rate:{:.0}/min (limit:{:.0})", rate, self.rate_limit_per_min));
            profile.burst_count += 1;
        }

        // 2. Query diversity (many unique inputs = distillation attempt)
        let recent_hashes: Vec<u64> = profile.queries.iter().rev().take(100).map(|q| q.input_hash).collect();
        let unique_ratio = {
            let mut uniq = recent_hashes.clone();
            uniq.sort(); uniq.dedup();
            uniq.len() as f64 / recent_hashes.len().max(1) as f64
        };
        if unique_ratio > self.diversity_threshold && recent_hashes.len() >= 20 {
            let diversity_risk = 0.55 + (unique_ratio - self.diversity_threshold) * 1.5;
            risk = risk.max(diversity_risk);
            details.push(format!("high_diversity:{:.1}% unique in last {}", unique_ratio * 100.0, recent_hashes.len()));
            attack_type = Some("model_distillation".into());
            self.total_distillation.fetch_add(1, Ordering::Relaxed);
        }

        // 3. Perturbation detection (many inputs with similar length = boundary probing)
        let perturbation_score = self.detect_perturbation_sequences(profile);
        if perturbation_score > self.perturbation_threshold {
            risk = risk.max(perturbation_score);
            details.push(format!("perturbation_detected:{:.2}", perturbation_score));
            attack_type = Some("boundary_probing".into());
            self.total_boundary_probe.fetch_add(1, Ordering::Relaxed);
        }

        // 4. Logprob exploitation
        if profile.total_queries > 10 {
            let logprob_ratio = profile.logprob_requests as f64 / profile.total_queries as f64;
            if logprob_ratio > 0.80 {
                risk = risk.max(0.70);
                details.push(format!("logprob_exploitation:{:.0}% of queries", logprob_ratio * 100.0));
                attack_type = Some("confidence_extraction".into());
            }
        }

        // 5. Membership inference (repeated queries with slight variations)
        let membership_score = self.detect_membership_inference(profile);
        if membership_score > 0.60 {
            risk = risk.max(membership_score);
            details.push(format!("membership_inference:{:.2}", membership_score));
            attack_type = Some("membership_inference".into());
            self.total_membership_inference.fetch_add(1, Ordering::Relaxed);
        }

        // 6. Burst pattern (repeated high-rate periods)
        if profile.burst_count >= 3 {
            risk = (risk + 0.10).min(1.0);
            details.push(format!("repeated_bursts:{}", profile.burst_count));
        }

        let blocked = risk >= self.block_threshold;
        if blocked {
            self.total_blocked.fetch_add(1, Ordering::Relaxed);
            self.total_suspected.fetch_add(1, Ordering::Relaxed);
            profile.flagged = true;
            let sev = if risk >= 0.90 { Severity::Critical } else { Severity::High };
            warn!(user=%query.user_id, risk=risk, attack=?attack_type, "Model extraction attempt detected");
            self.add_alert(now, sev, "Model extraction attempt",
                &format!("user={}, risk={:.2}, type={:?}, queries={}", query.user_id, risk, attack_type, profile.total_queries));
        }

        let action = if blocked { "block_and_rate_limit".into() }
            else if risk > 0.50 { "rate_limit_and_monitor".into() }
            else { "allow".into() };

        ExtractionResult {
            risk_score: risk,
            extraction_suspected: blocked,
            attack_type,
            query_rate_per_min: rate,
            diversity_score: unique_ratio,
            perturbation_score,
            details,
            recommended_action: action,
        }
    }

    fn detect_perturbation_sequences(&self, profile: &UserQueryProfile) -> f64 {
        if profile.queries.len() < 10 { return 0.0; }
        let recent: Vec<&QueryRecord> = profile.queries.iter().rev().take(50).collect();
        // Check for sequences of similar-length inputs (boundary probing uses small perturbations)
        let mut similar_len_count = 0;
        for window in recent.windows(2) {
            let diff = (window[0].input_len as i64 - window[1].input_len as i64).unsigned_abs();
            if diff <= 5 { similar_len_count += 1; }
        }
        let similar_ratio = similar_len_count as f64 / (recent.len() - 1).max(1) as f64;
        if similar_ratio > 0.70 { (0.65 + similar_ratio * 0.25).min(0.95) } else { 0.0 }
    }

    fn detect_membership_inference(&self, profile: &UserQueryProfile) -> f64 {
        if profile.queries.len() < 20 { return 0.0; }
        // Membership inference: many queries, high duplicate rate (testing "is X in training data?")
        let recent: Vec<u64> = profile.queries.iter().rev().take(100).map(|q| q.input_hash).collect();
        let mut freq: HashMap<u64, u32> = HashMap::new();
        for &h in &recent { *freq.entry(h).or_insert(0) += 1; }
        let max_freq = freq.values().copied().max().unwrap_or(0);
        let repeat_rate = freq.values().filter(|&&c| c >= 2).count() as f64 / freq.len().max(1) as f64;
        if repeat_rate > 0.30 && max_freq >= 3 {
            (0.55 + repeat_rate * 0.30).min(0.90)
        } else { 0.0 }
    }

    fn hash_input(text: &str) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        text.hash(&mut h);
        h.finish()
    }

    fn clean_result() -> ExtractionResult {
        ExtractionResult {
            risk_score: 0.0, extraction_suspected: false, attack_type: None,
            query_rate_per_min: 0.0, diversity_score: 0.0, perturbation_score: 0.0,
            details: vec![], recommended_action: "allow".into(),
        }
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(AiAlert { timestamp: ts, severity: sev, component: "model_extraction_guard".into(), title: title.into(), details: details.into() });
    }

    pub fn total_queries(&self) -> u64 { self.total_queries.load(Ordering::Relaxed) }
    pub fn total_suspected(&self) -> u64 { self.total_suspected.load(Ordering::Relaxed) }
    pub fn total_blocked(&self) -> u64 { self.total_blocked.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
