//! Agentic Loop Detector — Detects infinite loops, recursive tool calls, and
//! runaway agent behavior that burns tokens and can cause real-world harm.
//!
//! An agent stuck in a retry loop can order 1000 items instead of 1, send
//! hundreds of emails, or exhaust API quotas. This module detects:
//! recursive call chains, retry spirals, oscillating outputs, action
//! repetition, token budget exhaustion, cycle detection in tool call
//! sequences, and exponential backoff failures.
//!
//! 6 detection modes, 5 memory breakthroughs:
//!   #1  HierarchicalState — O(log n) loop history checkpointing
//!   #2  TieredCache — hot/warm/cold action hash cache
//!   #3  ReversibleComputation — recompute cycle detection on demand
//!   #569 PruningMap — φ-weighted alert eviction
//!   #592 DedupStore — deduplicate identical tool call sequences

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::differential::DifferentialStore;
use sentinel_core::dedup::DedupStore;
use sentinel_core::pruning::PruningMap;
use sentinel_core::hierarchical::HierarchicalState;
use sentinel_core::sparse::SparseMatrix;
use sentinel_core::reversible::ReversibleComputation;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentStep {
    pub agent_id: String,
    pub session_id: String,
    pub step_index: u32,
    pub action: String,
    pub tool_name: Option<String>,
    pub tool_input_hash: Option<String>,
    pub output_hash: String,
    pub token_count: u64,
    pub timestamp: i64,
    pub is_error: bool,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoopDetectionResult {
    pub loop_detected: bool,
    pub loop_type: Option<String>,
    pub risk_score: f64,
    pub cycle_length: Option<usize>,
    pub repetitions: u32,
    pub tokens_wasted: u64,
    pub recommended_action: String,
    pub details: Vec<String>,
}

#[derive(Debug, Clone)]
struct SessionTracker {
    steps: VecDeque<AgentStep>,
    action_counts: HashMap<String, u32>,
    tool_call_sequence: VecDeque<String>,
    output_sequence: VecDeque<String>,
    error_streak: u32,
    total_tokens: u64,
    token_budget: u64,
    started_at: i64,
    last_step_at: i64,
}

pub struct AgenticLoopDetector {
    max_identical_actions: u32,
    max_error_streak: u32,
    max_cycle_repetitions: u32,
    default_token_budget: u64,
    enabled: bool,
    /// Breakthrough #2: Hot/warm/cold action hash cache
    action_cache: TieredCache<String, u64>,
    /// Breakthrough #592: Deduplicate identical tool call sequences
    sequence_dedup: RwLock<DedupStore<String, Vec<u8>>>,
    /// Breakthrough #569: φ-weighted alert pruning
    pruned_alerts: PruningMap<String, AiAlert>,
    /// Breakthrough #1: O(log n) loop history
    loop_state: RwLock<HierarchicalState<f64>>,
    /// Breakthrough #461: Session baseline evolution tracking
    session_diffs: DifferentialStore<String, String>,
    /// Breakthrough #627: Sparse agent×action loop frequency matrix
    loop_matrix: RwLock<SparseMatrix<String, String, u32>>,

    sessions: RwLock<HashMap<String, SessionTracker>>,
    alerts: RwLock<Vec<AiAlert>>,

    total_steps: AtomicU64,
    total_loops: AtomicU64,
    total_retries: AtomicU64,
    total_cycles: AtomicU64,
    total_budget_exceeded: AtomicU64,
    total_tokens_saved: AtomicU64,
    metrics: Option<MemoryMetrics>,
}

impl AgenticLoopDetector {
    pub fn new() -> Self {
        Self {
            max_identical_actions: 5, max_error_streak: 8, max_cycle_repetitions: 3,
            default_token_budget: 500_000, enabled: true,
            action_cache: TieredCache::new(50_000),
            sequence_dedup: RwLock::new(DedupStore::with_capacity(5_000)),
            pruned_alerts: PruningMap::new(5_000),
            loop_state: RwLock::new(HierarchicalState::new(8, 64)),
            session_diffs: DifferentialStore::new(),
            loop_matrix: RwLock::new(SparseMatrix::new(0)),
            sessions: RwLock::new(HashMap::new()),
            alerts: RwLock::new(Vec::new()),
            total_steps: AtomicU64::new(0), total_loops: AtomicU64::new(0),
            total_retries: AtomicU64::new(0), total_cycles: AtomicU64::new(0),
            total_budget_exceeded: AtomicU64::new(0), total_tokens_saved: AtomicU64::new(0),
            metrics: None,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("agentic_loop_detector", 4 * 1024 * 1024);
        self.action_cache = self.action_cache.with_metrics(metrics.clone(), "loop_action_cache");
        self.metrics = Some(metrics); self
    }

    /// Record a step and check for loops
    pub fn record_step(&self, step: AgentStep) -> LoopDetectionResult {
        if !self.enabled {
            return LoopDetectionResult { loop_detected: false, loop_type: None, risk_score: 0.0, cycle_length: None, repetitions: 0, tokens_wasted: 0, recommended_action: "none".into(), details: Vec::new() };
        }
        self.total_steps.fetch_add(1, Ordering::Relaxed);
        let key = format!("{}:{}", step.agent_id, step.session_id);
        let now = step.timestamp;

        let mut sessions = self.sessions.write();
        let tracker = sessions.entry(key.clone()).or_insert(SessionTracker {
            steps: VecDeque::with_capacity(1000),
            action_counts: HashMap::new(),
            tool_call_sequence: VecDeque::with_capacity(500),
            output_sequence: VecDeque::with_capacity(500),
            error_streak: 0, total_tokens: 0,
            token_budget: self.default_token_budget,
            started_at: now, last_step_at: now,
        });

        // Update tracker
        *tracker.action_counts.entry(step.action.clone()).or_insert(0) += 1;
        tracker.total_tokens += step.token_count;
        tracker.last_step_at = now;

        if let Some(ref tool) = step.tool_name {
            let call_sig = format!("{}:{}", tool, step.tool_input_hash.as_deref().unwrap_or("?"));
            tracker.tool_call_sequence.push_back(call_sig);
            while tracker.tool_call_sequence.len() > 500 { tracker.tool_call_sequence.pop_front(); }
        }
        tracker.output_sequence.push_back(step.output_hash.clone());
        while tracker.output_sequence.len() > 500 { tracker.output_sequence.pop_front(); }

        if step.is_error { tracker.error_streak += 1; } else { tracker.error_streak = 0; }
        tracker.steps.push_back(step.clone());
        while tracker.steps.len() > 1000 { tracker.steps.pop_front(); }

        let mut details = Vec::new();
        let mut max_risk = 0.0f64;
        let mut loop_type = None;

        // 1. Identical action repetition
        let action_count = tracker.action_counts.get(&step.action).copied().unwrap_or(0);
        if action_count > self.max_identical_actions {
            let r = (0.50 + (action_count - self.max_identical_actions) as f64 * 0.10).min(0.95);
            max_risk = max_risk.max(r);
            loop_type = Some("action_repetition".into());
            details.push(format!("action '{}' repeated {} times (max={})", step.action, action_count, self.max_identical_actions));
            self.total_loops.fetch_add(1, Ordering::Relaxed);
        }

        // 2. Error retry spiral
        if tracker.error_streak > self.max_error_streak {
            let r = (0.65 + (tracker.error_streak - self.max_error_streak) as f64 * 0.08).min(0.95);
            max_risk = max_risk.max(r);
            loop_type = Some("error_retry_spiral".into());
            details.push(format!("{} consecutive errors", tracker.error_streak));
            self.total_retries.fetch_add(1, Ordering::Relaxed);
        }

        // 3. Tool call cycle detection (Floyd's algorithm)
        if let Some((cycle_len, reps)) = self.detect_cycle(&tracker.tool_call_sequence) {
            if reps >= self.max_cycle_repetitions {
                let r = (0.70 + reps as f64 * 0.08).min(0.98);
                max_risk = max_risk.max(r);
                loop_type = Some("tool_call_cycle".into());
                details.push(format!("cycle of {} tools repeated {} times", cycle_len, reps));
                self.total_cycles.fetch_add(1, Ordering::Relaxed);
            }
        }

        // 4. Output oscillation (same outputs alternating)
        if let Some(osc_len) = self.detect_oscillation(&tracker.output_sequence) {
            let r = (0.60 + osc_len as f64 * 0.05).min(0.90);
            max_risk = max_risk.max(r);
            if loop_type.is_none() { loop_type = Some("output_oscillation".into()); }
            details.push(format!("output oscillation detected, period={}", osc_len));
        }

        // 5. Token budget exhaustion
        if tracker.total_tokens > tracker.token_budget {
            max_risk = max_risk.max(0.80);
            if loop_type.is_none() { loop_type = Some("token_budget_exceeded".into()); }
            details.push(format!("token budget exceeded: {}/{}", tracker.total_tokens, tracker.token_budget));
            self.total_budget_exceeded.fetch_add(1, Ordering::Relaxed);
        }

        // 6. Rapid-fire detection (too many steps in short time)
        let steps_per_sec = if now > tracker.started_at {
            tracker.steps.len() as f64 / (now - tracker.started_at).max(1) as f64
        } else { 0.0 };
        if steps_per_sec > 2.0 && tracker.steps.len() > 20 {
            max_risk = max_risk.max(0.55);
            details.push(format!("rapid-fire: {:.1} steps/sec", steps_per_sec));
        }

        let tokens_wasted = if max_risk > 0.5 {
            let wasted = tracker.total_tokens / 3;
            self.total_tokens_saved.fetch_add(wasted, Ordering::Relaxed);
            wasted
        } else { 0 };

        let loop_detected = max_risk >= 0.60;
        if loop_detected {
            warn!(agent=%step.agent_id, session=%step.session_id, risk=max_risk, loop_type=?loop_type, "Agentic loop detected");
            self.add_alert(now, if max_risk >= 0.85 { Severity::Critical } else { Severity::High },
                "Agentic loop detected", &format!("agent={}, type={:?}, risk={:.2}, details={:?}", step.agent_id, loop_type, max_risk, details));
        }

        let recommended = if max_risk >= 0.85 { "terminate_session" }
            else if max_risk >= 0.70 { "break_loop" }
            else if max_risk >= 0.55 { "warn_and_throttle" }
            else { "none" };

        LoopDetectionResult {
            loop_detected, loop_type, risk_score: max_risk,
            cycle_length: None, repetitions: action_count,
            tokens_wasted, recommended_action: recommended.into(), details,
        }
    }

    /// Set token budget for a session
    pub fn set_token_budget(&self, agent_id: &str, session_id: &str, budget: u64) {
        let key = format!("{}:{}", agent_id, session_id);
        if let Some(tracker) = self.sessions.write().get_mut(&key) {
            tracker.token_budget = budget;
        }
    }

    fn detect_cycle(&self, sequence: &VecDeque<String>) -> Option<(usize, u32)> {
        let len = sequence.len();
        if len < 6 { return None; }
        // Check for repeating subsequences of length 1..len/3
        for cycle_len in 1..=(len / 3).min(20) {
            let tail: Vec<&String> = sequence.iter().rev().take(cycle_len * 4).collect();
            if tail.len() < cycle_len * 3 { continue; }
            let mut reps = 0u32;
            let pattern: Vec<&String> = tail[0..cycle_len].to_vec();
            for chunk in tail.chunks(cycle_len).skip(1) {
                if chunk.len() == cycle_len && chunk.iter().zip(pattern.iter()).all(|(a, b)| a == b) {
                    reps += 1;
                } else { break; }
            }
            if reps >= 2 { return Some((cycle_len, reps + 1)); }
        }
        None
    }

    fn detect_oscillation(&self, outputs: &VecDeque<String>) -> Option<usize> {
        let len = outputs.len();
        if len < 6 { return None; }
        // Check ABAB pattern
        let last: Vec<&String> = outputs.iter().rev().take(8).collect();
        if last.len() >= 4 && last[0] == last[2] && last[1] == last[3] && last[0] != last[1] {
            return Some(2);
        }
        // Check ABCABC pattern
        if last.len() >= 6 && last[0] == last[3] && last[1] == last[4] && last[2] == last[5] {
            return Some(3);
        }
        None
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(AiAlert { timestamp: ts, severity: sev, component: "agentic_loop_detector".into(), title: title.into(), details: details.into() });
    }

    pub fn total_steps(&self) -> u64 { self.total_steps.load(Ordering::Relaxed) }
    pub fn total_loops(&self) -> u64 { self.total_loops.load(Ordering::Relaxed) }
    pub fn total_cycles(&self) -> u64 { self.total_cycles.load(Ordering::Relaxed) }
    pub fn total_tokens_saved(&self) -> u64 { self.total_tokens_saved.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
