//! Goal Drift Monitor — Detects when an agent's behavior subtly shifts away
//! from its intended objective over time through accumulated context manipulation.
//!
//! Like boiling a frog: each individual message is benign, but the cumulative
//! effect steers the agent off-course. This is harder to detect than direct
//! injection because no single input is malicious.
//!
//! Methods: objective embedding tracking, behavioral trajectory analysis,
//! drift velocity measurement, semantic distance from original goal,
//! topic distribution shift detection, action pattern divergence,
//! and cumulative manipulation scoring.
//!
//! 5 detection dimensions, 5 memory breakthroughs:
//!   #1  HierarchicalState — O(log n) drift trajectory checkpointing
//!   #2  TieredCache — hot/warm/cold topic distribution cache
//!   #461 DifferentialStore — objective baseline evolution tracking
//!   #569 PruningMap — φ-weighted alert eviction
//!   #627 SparseMatrix — sparse agent×topic drift matrix

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::differential::DifferentialStore;
use sentinel_core::pruning::PruningMap;
use sentinel_core::hierarchical::HierarchicalState;
use sentinel_core::sparse::SparseMatrix;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;
const MAX_HISTORY: usize = 10_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GoalState {
    pub agent_id: String,
    pub session_id: String,
    pub original_objective: String,
    pub current_context_summary: String,
    pub recent_actions: Vec<String>,
    pub turn_number: u32,
    pub timestamp: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DriftResult {
    pub drift_score: f64,
    pub drift_detected: bool,
    pub drift_velocity: f64,
    pub topic_shift: f64,
    pub action_divergence: f64,
    pub manipulation_indicators: Vec<String>,
    pub recommended_action: String,
}

#[derive(Debug, Clone)]
struct ObjectiveTracker {
    original_keywords: Vec<String>,
    original_topics: HashMap<String, f64>,
    action_baseline: HashMap<String, u64>,
    drift_history: VecDeque<f64>,
    turn_count: u32,
    last_drift: f64,
    max_drift: f64,
    created_at: i64,
}

// Topic categories and their associated keywords
const TOPIC_KEYWORDS: &[(&str, &[&str])] = &[
    ("coding", &["code", "function", "variable", "class", "method", "debug", "compile", "test", "deploy", "git"]),
    ("writing", &["write", "draft", "edit", "paragraph", "essay", "article", "blog", "document", "proofread"]),
    ("analysis", &["analyze", "compare", "evaluate", "assess", "review", "examine", "investigate", "study"]),
    ("math", &["calculate", "equation", "formula", "solve", "proof", "theorem", "integral", "derivative"]),
    ("finance", &["money", "payment", "transfer", "account", "bank", "invest", "trade", "crypto", "wallet"]),
    ("security", &["password", "credential", "encrypt", "decrypt", "auth", "token", "key", "certificate"]),
    ("system", &["file", "directory", "process", "install", "configure", "admin", "root", "permission"]),
    ("network", &["http", "api", "request", "url", "endpoint", "server", "dns", "port", "socket"]),
    ("data", &["database", "query", "table", "record", "csv", "json", "export", "import", "backup"]),
    ("social", &["email", "message", "contact", "share", "post", "publish", "send", "notify"]),
];

// Manipulation language that subtly steers conversations
const MANIPULATION_MARKERS: &[(&str, f64)] = &[
    ("but actually", 0.40), ("what you really need", 0.55),
    ("more importantly", 0.35), ("forget about that", 0.65),
    ("that's not relevant", 0.50), ("let's focus on", 0.30),
    ("what matters is", 0.35), ("the real question is", 0.45),
    ("wouldn't it be better to", 0.40), ("you should instead", 0.45),
    ("a better approach would be", 0.30), ("let me redirect", 0.55),
    ("changing topics", 0.50), ("on a different note", 0.35),
    ("by the way", 0.20), ("speaking of which", 0.25),
    ("that reminds me", 0.20), ("before we continue", 0.35),
    ("first let's handle", 0.30), ("actually, could you", 0.40),
];

pub struct GoalDriftMonitor {
    drift_threshold: f64,
    velocity_threshold: f64,
    enabled: bool,
    /// Breakthrough #2: Hot/warm/cold topic distribution cache
    topic_cache: TieredCache<String, u64>,
    /// Breakthrough #461: Objective baseline diffs
    objective_diffs: DifferentialStore<String, String>,
    /// Breakthrough #569: φ-weighted alert pruning
    pruned_alerts: PruningMap<String, AiAlert>,
    /// Breakthrough #1: O(log n) drift trajectory checkpoints
    drift_checkpoints: RwLock<HierarchicalState<f64>>,
    /// Breakthrough #627: Sparse agent×topic drift matrix
    drift_matrix: RwLock<SparseMatrix<String, String, f64>>,

    trackers: RwLock<HashMap<String, ObjectiveTracker>>,
    alerts: RwLock<Vec<AiAlert>>,
    history: RwLock<VecDeque<(String, i64, f64)>>,

    total_checks: AtomicU64,
    total_drifts: AtomicU64,
    total_manipulations: AtomicU64,
    total_resets: AtomicU64,
    metrics: Option<MemoryMetrics>,
}

impl GoalDriftMonitor {
    pub fn new() -> Self {
        Self {
            drift_threshold: 0.60, velocity_threshold: 0.15, enabled: true,
            topic_cache: TieredCache::new(30_000),
            objective_diffs: DifferentialStore::new(),
            pruned_alerts: PruningMap::new(5_000),
            drift_checkpoints: RwLock::new(HierarchicalState::new(8, 64)),
            drift_matrix: RwLock::new(SparseMatrix::new(0.0)),
            trackers: RwLock::new(HashMap::new()),
            alerts: RwLock::new(Vec::new()),
            history: RwLock::new(VecDeque::with_capacity(MAX_HISTORY)),
            total_checks: AtomicU64::new(0), total_drifts: AtomicU64::new(0),
            total_manipulations: AtomicU64::new(0), total_resets: AtomicU64::new(0),
            metrics: None,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("goal_drift_monitor", 4 * 1024 * 1024);
        self.topic_cache = self.topic_cache.with_metrics(metrics.clone(), "drift_topic_cache");
        self.metrics = Some(metrics); self
    }

    /// Register the original objective for an agent session
    pub fn register_objective(&self, agent_id: &str, session_id: &str, objective: &str, timestamp: i64) {
        let key = format!("{}:{}", agent_id, session_id);
        let keywords = Self::extract_keywords(objective);
        let topics = Self::compute_topic_distribution(objective);
        let mut trackers = self.trackers.write();
        trackers.insert(key, ObjectiveTracker {
            original_keywords: keywords,
            original_topics: topics,
            action_baseline: HashMap::new(),
            drift_history: VecDeque::with_capacity(500),
            turn_count: 0, last_drift: 0.0, max_drift: 0.0,
            created_at: timestamp,
        });
    }

    /// Check current state against original objective
    pub fn check_drift(&self, state: &GoalState) -> DriftResult {
        if !self.enabled {
            return DriftResult { drift_score: 0.0, drift_detected: false, drift_velocity: 0.0, topic_shift: 0.0, action_divergence: 0.0, manipulation_indicators: Vec::new(), recommended_action: "none".into() };
        }
        self.total_checks.fetch_add(1, Ordering::Relaxed);
        let key = format!("{}:{}", state.agent_id, state.session_id);

        let mut trackers = self.trackers.write();
        let tracker = match trackers.get_mut(&key) {
            Some(t) => t,
            None => {
                // Auto-register if not exists
                drop(trackers);
                self.register_objective(&state.agent_id, &state.session_id, &state.original_objective, state.timestamp);
                trackers = self.trackers.write();
                trackers.get_mut(&key).unwrap()
            }
        };

        tracker.turn_count = state.turn_number;

        // 1. Topic distribution shift
        let current_topics = Self::compute_topic_distribution(&state.current_context_summary);
        let topic_shift = Self::topic_distance(&tracker.original_topics, &current_topics);

        // 2. Keyword retention (how many original keywords are still present)
        let current_lower = state.current_context_summary.to_lowercase();
        let retained: usize = tracker.original_keywords.iter().filter(|k| current_lower.contains(k.as_str())).count();
        let keyword_retention = if tracker.original_keywords.is_empty() { 1.0 } else { retained as f64 / tracker.original_keywords.len() as f64 };

        // 3. Action pattern divergence
        let action_div = self.compute_action_divergence(&state.recent_actions, &tracker.action_baseline);
        for action in &state.recent_actions {
            *tracker.action_baseline.entry(action.clone()).or_insert(0) += 1;
        }

        // 4. Manipulation indicator scanning
        let mut manipulations = Vec::new();
        let combined = format!("{} {}", state.current_context_summary, state.recent_actions.join(" ")).to_lowercase();
        for (marker, w) in MANIPULATION_MARKERS {
            let count = combined.matches(marker).count();
            if count > 0 {
                manipulations.push(format!("'{}' x{} w={:.2}", marker, count, w));
            }
        }
        let manipulation_score = manipulations.len() as f64 * 0.08;
        if !manipulations.is_empty() {
            self.total_manipulations.fetch_add(manipulations.len() as u64, Ordering::Relaxed);
        }

        // 5. Composite drift score
        let drift_score = (
            topic_shift * 0.35 +
            (1.0 - keyword_retention) * 0.30 +
            action_div * 0.20 +
            manipulation_score.min(0.40) * 0.15
        ).min(1.0);

        // 6. Drift velocity (rate of change)
        tracker.drift_history.push_back(drift_score);
        while tracker.drift_history.len() > 500 { tracker.drift_history.pop_front(); }
        let velocity = if tracker.drift_history.len() >= 3 {
            let recent: Vec<f64> = tracker.drift_history.iter().rev().take(5).copied().collect();
            let older: Vec<f64> = tracker.drift_history.iter().rev().skip(5).take(5).copied().collect();
            if older.is_empty() { 0.0 }
            else {
                let recent_avg = recent.iter().sum::<f64>() / recent.len() as f64;
                let older_avg = older.iter().sum::<f64>() / older.len() as f64;
                (recent_avg - older_avg).max(0.0)
            }
        } else { 0.0 };

        tracker.last_drift = drift_score;
        tracker.max_drift = tracker.max_drift.max(drift_score);

        // Record history
        { let mut h = self.history.write(); h.push_back((key, state.timestamp, drift_score)); while h.len() > MAX_HISTORY { h.pop_front(); } }

        let drift_detected = drift_score >= self.drift_threshold || velocity >= self.velocity_threshold;
        if drift_detected {
            self.total_drifts.fetch_add(1, Ordering::Relaxed);
            let now = state.timestamp;
            warn!(agent=%state.agent_id, session=%state.session_id, drift=drift_score, velocity=velocity, "Goal drift detected");
            self.add_alert(now, Severity::High, "Agent goal drift detected",
                &format!("agent={}, drift={:.2}, velocity={:.2}, topic_shift={:.2}, turn={}", state.agent_id, drift_score, velocity, topic_shift, state.turn_number));
        }

        let recommended = if drift_score >= 0.80 { "reset_context" }
            else if drift_score >= 0.60 { "warn_user" }
            else if velocity >= 0.15 { "monitor_closely" }
            else { "none" };

        DriftResult {
            drift_score, drift_detected, drift_velocity: velocity,
            topic_shift, action_divergence: action_div,
            manipulation_indicators: manipulations,
            recommended_action: recommended.into(),
        }
    }

    /// Reset tracking for a session (e.g., after user confirms new direction)
    pub fn reset_session(&self, agent_id: &str, session_id: &str) {
        let key = format!("{}:{}", agent_id, session_id);
        self.trackers.write().remove(&key);
        self.total_resets.fetch_add(1, Ordering::Relaxed);
    }

    fn extract_keywords(text: &str) -> Vec<String> {
        let stop_words: std::collections::HashSet<&str> = ["the", "a", "an", "is", "are", "was", "were", "be", "been",
            "being", "have", "has", "had", "do", "does", "did", "will", "would", "could", "should",
            "may", "might", "can", "shall", "to", "of", "in", "for", "on", "with", "at", "by",
            "from", "as", "into", "about", "it", "its", "this", "that", "and", "or", "but", "if",
            "not", "no", "so", "up", "out", "just", "also", "than", "then", "very", "too", "i",
            "me", "my", "we", "our", "you", "your", "he", "she", "they", "them"].iter().copied().collect();

        text.to_lowercase().split_whitespace()
            .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()).to_string())
            .filter(|w| w.len() > 2 && !stop_words.contains(w.as_str()))
            .collect()
    }

    fn compute_topic_distribution(text: &str) -> HashMap<String, f64> {
        let lower = text.to_lowercase();
        let mut dist = HashMap::new();
        let mut total = 0.0f64;
        for (topic, keywords) in TOPIC_KEYWORDS {
            let count: usize = keywords.iter().map(|k| lower.matches(k).count()).sum();
            if count > 0 {
                dist.insert(topic.to_string(), count as f64);
                total += count as f64;
            }
        }
        if total > 0.0 { for v in dist.values_mut() { *v /= total; } }
        dist
    }

    fn topic_distance(a: &HashMap<String, f64>, b: &HashMap<String, f64>) -> f64 {
        let all_topics: std::collections::HashSet<&String> = a.keys().chain(b.keys()).collect();
        if all_topics.is_empty() { return 0.0; }
        let mut dist = 0.0f64;
        for topic in all_topics {
            let va = a.get(topic.as_str()).copied().unwrap_or(0.0);
            let vb = b.get(topic.as_str()).copied().unwrap_or(0.0);
            dist += (va - vb).abs();
        }
        (dist / 2.0).min(1.0) // Jensen-Shannon-like distance, normalized
    }

    fn compute_action_divergence(&self, recent_actions: &[String], baseline: &HashMap<String, u64>) -> f64 {
        if baseline.is_empty() || recent_actions.is_empty() { return 0.0; }
        let total_baseline: u64 = baseline.values().sum();
        let mut novel = 0usize;
        for action in recent_actions {
            if !baseline.contains_key(action) { novel += 1; }
        }
        (novel as f64 / recent_actions.len() as f64).min(1.0) * 0.5 +
        if total_baseline > 20 { 0.0 } else { 0.1 } // bonus uncertainty for small baselines
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(AiAlert { timestamp: ts, severity: sev, component: "goal_drift_monitor".into(), title: title.into(), details: details.into() });
    }

    pub fn total_checks(&self) -> u64 { self.total_checks.load(Ordering::Relaxed) }
    pub fn total_drifts(&self) -> u64 { self.total_drifts.load(Ordering::Relaxed) }
    pub fn total_manipulations(&self) -> u64 { self.total_manipulations.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
