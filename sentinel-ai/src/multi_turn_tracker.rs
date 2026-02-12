//! Multi-Turn Jailbreak Tracker — detects conversation-level attack patterns.
//!
//! Individual messages may pass the prompt guard, but a carefully crafted
//! sequence of messages can constitute a jailbreak. This module tracks
//! conversation state and detects multi-turn attack strategies:
//!
//!  1. **Crescendo attacks** — gradually escalating requests
//!  2. **Context poisoning** — seeding benign context later weaponized
//!  3. **Role-play escalation** — "let's play a game" → character → harmful request
//!  4. **Trust building** — many normal exchanges before the attack turn
//!  5. **Instruction fragmentation** — attack split across multiple turns
//!  6. **Persona persistence** — maintaining a jailbroken persona across turns
//!  7. **Refusal bypass loops** — rephrasing after each refusal to find a gap
//!
//! Memory optimizations:
//! - **#2 Tiered Cache**: Session fingerprint cache
//! - **#1 HierarchicalState**: Conversation risk state tracking
//! - **#4 PruningMap**: φ-weighted session pruning

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::differential::DifferentialStore;
use sentinel_core::hierarchical::HierarchicalState;
use sentinel_core::pruning::PruningMap;
use sentinel_core::sparse::SparseMatrix;
use sentinel_core::dedup::DedupStore;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;
const MAX_SESSION_TURNS: usize = 200;
const MAX_SESSIONS: usize = 10_000;

// ── Crescendo signal patterns (individually weak, strong in sequence) ────────

const CRESCENDO_STAGE1: &[&str] = &[
    "let's play a game", "imagine a scenario", "let me tell you a story",
    "can we do a creative writing exercise", "i want to roleplay",
    "let's do a thought experiment", "hypothetically speaking",
    "for a novel i'm writing", "in a fictional world",
    "let's pretend", "just for fun", "as an exercise",
];

const CRESCENDO_STAGE2: &[&str] = &[
    "you are now a character", "in this story you are", "your character would",
    "stay in character", "don't break character", "remember you're playing",
    "the character has no restrictions", "this character can say anything",
    "the character doesn't follow rules", "in this world there are no",
    "your character believes", "as this character you must",
];

const CRESCENDO_STAGE3: &[&str] = &[
    "now as that character", "staying in character", "what would the character say about",
    "how would the character", "the character needs to explain",
    "continue as the character", "the character would answer",
    "don't forget you're the character", "give me the character's response",
];

// ── Refusal bypass patterns ─────────────────────────────────────────────────

const REFUSAL_INDICATORS: &[&str] = &[
    "i can't", "i cannot", "i'm unable", "i am unable",
    "i won't", "i will not", "i'm not able", "that's not something",
    "i must decline", "against my guidelines", "i apologize but",
    "as an ai", "my purpose is to", "safety guidelines",
];

const REPHRASE_INDICATORS: &[&str] = &[
    "ok but what if", "fine, then", "let me rephrase",
    "what about", "how about instead", "ok let's try",
    "forget that, instead", "never mind, can you",
    "ok but hypothetically", "what if i said",
    "try again but this time", "let me ask differently",
    "please reconsider", "surely you can",
];

// ── Persona persistence detection ───────────────────────────────────────────

const PERSONA_REINFORCEMENT: &[&str] = &[
    "remember you are", "you're still", "don't forget your role",
    "stay as", "keep being", "you promised to be",
    "you said you would", "you agreed to", "earlier you said",
    "go back to being", "return to the character",
    "continue from where", "pick up where you left off",
];

// ── Types ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ConversationTurn {
    pub session_id: String,
    pub user_id: String,
    pub role: TurnRole,
    pub content: String,
    pub timestamp: i64,
    pub prompt_guard_score: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TurnRole { User, Assistant, System, Tool }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MultiTurnResult {
    pub risk_score: f64,
    pub attack_detected: bool,
    pub attack_type: Option<String>,
    pub conversation_risk_trend: String,
    pub turns_analyzed: usize,
    pub refusal_bypass_count: u32,
    pub crescendo_stage: u32,
    pub persona_persistence: bool,
    pub details: Vec<String>,
    pub recommended_action: String,
}

#[derive(Debug, Clone)]
struct SessionState {
    turns: VecDeque<TurnRecord>,
    cumulative_risk: f64,
    risk_history: VecDeque<f64>,
    crescendo_stage: u32,
    refusal_count: u32,
    rephrase_after_refusal: u32,
    persona_active: bool,
    persona_turns_held: u32,
    last_refusal_turn: Option<usize>,
    user_id: String,
    created_at: i64,
    last_activity: i64,
}

#[derive(Debug, Clone)]
struct TurnRecord {
    role: TurnRole,
    lower_content: String,
    prompt_score: f64,
    timestamp: i64,
    signals: Vec<String>,
}

// ── Main struct ─────────────────────────────────────────────────────────────

pub struct MultiTurnTracker {
    crescendo_threshold: f64,
    refusal_bypass_threshold: u32,
    persona_persistence_threshold: u32,
    enabled: bool,

    session_cache: TieredCache<String, u64>,
    risk_state: RwLock<HierarchicalState<f64>>,
    session_pruning: PruningMap<String, i64>,
    /// Breakthrough #461: Session baseline evolution tracking
    session_diffs: DifferentialStore<String, String>,
    /// Breakthrough #627: Sparse session×attack-type matrix
    attack_matrix: RwLock<SparseMatrix<String, String, u64>>,
    /// Breakthrough #592: Content-addressed dedup for turn fingerprints
    turn_dedup: DedupStore<String, String>,

    sessions: RwLock<HashMap<String, SessionState>>,
    alerts: RwLock<Vec<AiAlert>>,

    total_turns: AtomicU64,
    total_attacks: AtomicU64,
    total_crescendo: AtomicU64,
    total_refusal_bypass: AtomicU64,
    total_persona_persist: AtomicU64,
    total_fragmentation: AtomicU64,
    total_trust_exploit: AtomicU64,

    metrics: Option<MemoryMetrics>,
}

impl MultiTurnTracker {
    pub fn new() -> Self {
        Self {
            crescendo_threshold: 0.65,
            refusal_bypass_threshold: 3,
            persona_persistence_threshold: 5,
            enabled: true,
            session_cache: TieredCache::new(30_000),
            risk_state: RwLock::new(HierarchicalState::new(8, 64)),
            session_pruning: PruningMap::new(MAX_SESSIONS),
            session_diffs: DifferentialStore::new(),
            attack_matrix: RwLock::new(SparseMatrix::new(0)),
            turn_dedup: DedupStore::new(),
            sessions: RwLock::new(HashMap::new()),
            alerts: RwLock::new(Vec::new()),
            total_turns: AtomicU64::new(0),
            total_attacks: AtomicU64::new(0),
            total_crescendo: AtomicU64::new(0),
            total_refusal_bypass: AtomicU64::new(0),
            total_persona_persist: AtomicU64::new(0),
            total_fragmentation: AtomicU64::new(0),
            total_trust_exploit: AtomicU64::new(0),
            metrics: None,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("multi_turn_tracker", 6 * 1024 * 1024);
        self.session_cache = self.session_cache.with_metrics(metrics.clone(), "multi_turn_cache");
        self.metrics = Some(metrics);
        self
    }

    // ── Main API ────────────────────────────────────────────────────────────

    pub fn record_turn(&self, turn: &ConversationTurn) -> MultiTurnResult {
        if !self.enabled {
            return Self::empty_result();
        }
        self.total_turns.fetch_add(1, Ordering::Relaxed);
        let key = turn.session_id.clone();
        let lower = turn.content.to_lowercase();
        let now = turn.timestamp;

        let mut sessions = self.sessions.write();
        if sessions.len() > MAX_SESSIONS {
            let cutoff = now - 7200;
            sessions.retain(|_, s| s.last_activity > cutoff);
        }

        let session = sessions.entry(key.clone()).or_insert_with(|| SessionState {
            turns: VecDeque::with_capacity(MAX_SESSION_TURNS),
            cumulative_risk: 0.0,
            risk_history: VecDeque::with_capacity(100),
            crescendo_stage: 0,
            refusal_count: 0,
            rephrase_after_refusal: 0,
            persona_active: false,
            persona_turns_held: 0,
            last_refusal_turn: None,
            user_id: turn.user_id.clone(),
            created_at: now,
            last_activity: now,
        });
        session.last_activity = now;

        // Detect signals in this turn
        let mut signals = Vec::new();
        let mut turn_risk = turn.prompt_guard_score;

        match turn.role {
            TurnRole::User => {
                // 1. Crescendo detection
                let stage_signal = self.detect_crescendo_signal(&lower, session.crescendo_stage);
                if let Some((new_stage, sig)) = stage_signal {
                    session.crescendo_stage = new_stage;
                    signals.push(sig);
                    turn_risk = turn_risk.max(0.30 + new_stage as f64 * 0.15);
                }

                // 2. Refusal bypass detection
                if let Some(last_ref) = session.last_refusal_turn {
                    let turns_since = session.turns.len() - last_ref;
                    if turns_since <= 3 && Self::matches_any(&lower, REPHRASE_INDICATORS) {
                        session.rephrase_after_refusal += 1;
                        signals.push("rephrase_after_refusal".into());
                        turn_risk = turn_risk.max(0.50 + session.rephrase_after_refusal as f64 * 0.10);
                    }
                }

                // 3. Persona persistence detection
                if Self::matches_any(&lower, PERSONA_REINFORCEMENT) {
                    if session.persona_active {
                        session.persona_turns_held += 1;
                        signals.push(format!("persona_reinforcement_turn_{}", session.persona_turns_held));
                        turn_risk = turn_risk.max(0.55 + session.persona_turns_held as f64 * 0.05);
                    } else {
                        session.persona_active = true;
                        session.persona_turns_held = 1;
                        signals.push("persona_activated".into());
                    }
                }

                // 4. Instruction fragmentation (combine recent user messages)
                let frag_score = self.detect_fragmentation(session, &lower);
                if frag_score > 0.60 {
                    signals.push("instruction_fragmentation".into());
                    turn_risk = turn_risk.max(frag_score);
                }

                // 5. Trust exploitation (many benign turns then spike)
                let trust_exploit = self.detect_trust_exploitation(session, turn_risk);
                if trust_exploit > 0.0 {
                    signals.push("trust_exploitation".into());
                    turn_risk = turn_risk.max(trust_exploit);
                }
            }
            TurnRole::Assistant => {
                // Track refusals
                if Self::matches_any(&lower, REFUSAL_INDICATORS) {
                    session.refusal_count += 1;
                    session.last_refusal_turn = Some(session.turns.len());
                    signals.push("assistant_refusal".into());
                }
            }
            _ => {}
        }

        // Update risk history
        session.cumulative_risk = session.cumulative_risk * 0.85 + turn_risk * 0.15;
        session.risk_history.push_back(turn_risk);
        if session.risk_history.len() > 100 { session.risk_history.pop_front(); }

        // Store turn record
        let record = TurnRecord {
            role: turn.role.clone(),
            lower_content: lower,
            prompt_score: turn.prompt_guard_score,
            timestamp: now,
            signals: signals.clone(),
        };
        session.turns.push_back(record);
        while session.turns.len() > MAX_SESSION_TURNS { session.turns.pop_front(); }

        // Compute final session risk
        let (final_risk, attack_type, action) = self.compute_session_risk(session);
        let attack_detected = final_risk >= self.crescendo_threshold;
        let trend = self.compute_risk_trend(session);

        if attack_detected {
            self.total_attacks.fetch_add(1, Ordering::Relaxed);
            match attack_type.as_deref() {
                Some("crescendo") => { self.total_crescendo.fetch_add(1, Ordering::Relaxed); }
                Some("refusal_bypass") => { self.total_refusal_bypass.fetch_add(1, Ordering::Relaxed); }
                Some("persona_persistence") => { self.total_persona_persist.fetch_add(1, Ordering::Relaxed); }
                Some("fragmentation") => { self.total_fragmentation.fetch_add(1, Ordering::Relaxed); }
                Some("trust_exploitation") => { self.total_trust_exploit.fetch_add(1, Ordering::Relaxed); }
                _ => {}
            }
            let sev = if final_risk >= 0.85 { Severity::Critical } else { Severity::High };
            warn!(
                session=%key, risk=final_risk, attack=?attack_type, turns=session.turns.len(),
                "Multi-turn attack detected"
            );
            self.add_alert(now, sev, "Multi-turn jailbreak detected",
                &format!("session={}, type={:?}, risk={:.2}, turns={}, user={}",
                    key, attack_type, final_risk, session.turns.len(), session.user_id));
        }

        MultiTurnResult {
            risk_score: final_risk,
            attack_detected,
            attack_type,
            conversation_risk_trend: trend,
            turns_analyzed: session.turns.len(),
            refusal_bypass_count: session.rephrase_after_refusal,
            crescendo_stage: session.crescendo_stage,
            persona_persistence: session.persona_active && session.persona_turns_held >= self.persona_persistence_threshold,
            details: signals,
            recommended_action: action,
        }
    }

    // ── Crescendo detection ─────────────────────────────────────────────────

    fn detect_crescendo_signal(&self, text: &str, current_stage: u32) -> Option<(u32, String)> {
        match current_stage {
            0 => {
                if Self::matches_any(text, CRESCENDO_STAGE1) {
                    Some((1, "crescendo_stage1_setup".into()))
                } else { None }
            }
            1 => {
                if Self::matches_any(text, CRESCENDO_STAGE2) {
                    Some((2, "crescendo_stage2_character".into()))
                } else if Self::matches_any(text, CRESCENDO_STAGE1) {
                    Some((1, "crescendo_stage1_reinforced".into()))
                } else { None }
            }
            2 => {
                if Self::matches_any(text, CRESCENDO_STAGE3) {
                    Some((3, "crescendo_stage3_exploit".into()))
                } else if Self::matches_any(text, CRESCENDO_STAGE2) {
                    Some((2, "crescendo_stage2_reinforced".into()))
                } else { None }
            }
            _ => {
                if Self::matches_any(text, CRESCENDO_STAGE3) || Self::matches_any(text, CRESCENDO_STAGE2) {
                    Some((current_stage, "crescendo_sustained".into()))
                } else { None }
            }
        }
    }

    // ── Fragmentation detection ─────────────────────────────────────────────

    fn detect_fragmentation(&self, session: &SessionState, current: &str) -> f64 {
        let user_turns: Vec<&str> = session.turns.iter()
            .rev().take(5)
            .filter(|t| t.role == TurnRole::User)
            .map(|t| t.lower_content.as_str())
            .collect();
        if user_turns.is_empty() { return 0.0; }

        let combined = format!("{} {}", user_turns.join(" "), current);
        let attack_phrases = [
            "ignore previous instructions", "bypass your safety",
            "you are now", "override your system", "forget your guidelines",
            "disregard all previous", "enable unrestricted mode",
        ];
        let mut frag_score = 0.0f64;
        for phrase in &attack_phrases {
            if combined.contains(phrase) && !current.contains(phrase) {
                frag_score = frag_score.max(0.80);
            }
        }
        // Also check if individual words from attack phrases are spread across turns
        let attack_words: Vec<&str> = vec!["ignore", "bypass", "override", "unrestricted", "jailbreak", "hack"];
        let mut word_hits = 0;
        for w in &attack_words {
            if user_turns.iter().any(|t| t.contains(w)) || current.contains(w) { word_hits += 1; }
        }
        if word_hits >= 3 {
            frag_score = frag_score.max(0.65 + word_hits as f64 * 0.05);
        }
        frag_score
    }

    // ── Trust exploitation ──────────────────────────────────────────────────

    fn detect_trust_exploitation(&self, session: &SessionState, current_risk: f64) -> f64 {
        if session.turns.len() < 8 { return 0.0; }
        let recent_avg: f64 = session.risk_history.iter().rev().take(3)
            .copied().sum::<f64>() / 3.0f64.min(session.risk_history.len() as f64).max(1.0);
        let historical_avg: f64 = session.risk_history.iter().rev().skip(3)
            .copied().sum::<f64>() / (session.risk_history.len().saturating_sub(3).max(1) as f64);

        // Sudden spike after sustained low-risk conversation
        if historical_avg < 0.15 && current_risk > 0.50 && session.turns.len() > 10 {
            let multiplier = (session.turns.len() as f64 / 10.0).min(1.5);
            return (0.70 * multiplier).min(0.95);
        }
        0.0
    }

    // ── Session risk computation ────────────────────────────────────────────

    fn compute_session_risk(&self, session: &SessionState) -> (f64, Option<String>, String) {
        let mut max_risk = session.cumulative_risk;
        let mut attack_type = None;
        let mut action = "monitor".to_string();

        // Crescendo attack
        if session.crescendo_stage >= 3 {
            let crescendo_risk = 0.60 + session.crescendo_stage as f64 * 0.10;
            if crescendo_risk > max_risk {
                max_risk = crescendo_risk;
                attack_type = Some("crescendo".into());
                action = "block_and_reset_session".into();
            }
        }

        // Refusal bypass loops
        if session.rephrase_after_refusal >= self.refusal_bypass_threshold {
            let bypass_risk = 0.65 + session.rephrase_after_refusal as f64 * 0.08;
            if bypass_risk > max_risk {
                max_risk = bypass_risk;
                attack_type = Some("refusal_bypass".into());
                action = "block_and_warn_user".into();
            }
        }

        // Persona persistence
        if session.persona_active && session.persona_turns_held >= self.persona_persistence_threshold {
            let persona_risk = 0.70 + session.persona_turns_held as f64 * 0.03;
            if persona_risk > max_risk {
                max_risk = persona_risk;
                attack_type = Some("persona_persistence".into());
                action = "reset_persona".into();
            }
        }

        // Check for fragmentation from recent signals
        if let Some(last_turn) = session.turns.back() {
            if last_turn.signals.contains(&"instruction_fragmentation".to_string()) {
                let frag_risk = 0.75;
                if frag_risk > max_risk {
                    max_risk = frag_risk;
                    attack_type = Some("fragmentation".into());
                    action = "block_and_log".into();
                }
            }
            if last_turn.signals.contains(&"trust_exploitation".to_string()) {
                let trust_risk = 0.80;
                if trust_risk > max_risk {
                    max_risk = trust_risk;
                    attack_type = Some("trust_exploitation".into());
                    action = "block_and_escalate".into();
                }
            }
        }

        (max_risk.min(1.0), attack_type, action)
    }

    // ── Risk trend ──────────────────────────────────────────────────────────

    fn compute_risk_trend(&self, session: &SessionState) -> String {
        if session.risk_history.len() < 3 { return "insufficient_data".into(); }
        let recent: f64 = session.risk_history.iter().rev().take(3).copied().sum::<f64>() / 3.0;
        let older: f64 = session.risk_history.iter().rev().skip(3).take(3).copied().sum::<f64>()
            / 3.0f64.min(session.risk_history.len().saturating_sub(3) as f64).max(1.0);
        let delta = recent - older;
        if delta > 0.15 { "escalating".into() }
        else if delta < -0.10 { "deescalating".into() }
        else { "stable".into() }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn matches_any(text: &str, patterns: &[&str]) -> bool {
        patterns.iter().any(|p| text.contains(p))
    }

    fn empty_result() -> MultiTurnResult {
        MultiTurnResult {
            risk_score: 0.0, attack_detected: false, attack_type: None,
            conversation_risk_trend: "stable".into(), turns_analyzed: 0,
            refusal_bypass_count: 0, crescendo_stage: 0,
            persona_persistence: false, details: vec![],
            recommended_action: "none".into(),
        }
    }

    pub fn reset_session(&self, session_id: &str) {
        self.sessions.write().remove(session_id);
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(AiAlert { timestamp: ts, severity: sev, component: "multi_turn_tracker".into(), title: title.into(), details: details.into() });
    }

    // ── Query methods ───────────────────────────────────────────────────────

    pub fn total_turns(&self) -> u64 { self.total_turns.load(Ordering::Relaxed) }
    pub fn total_attacks(&self) -> u64 { self.total_attacks.load(Ordering::Relaxed) }
    pub fn total_crescendo(&self) -> u64 { self.total_crescendo.load(Ordering::Relaxed) }
    pub fn total_refusal_bypass(&self) -> u64 { self.total_refusal_bypass.load(Ordering::Relaxed) }
    pub fn total_persona_persist(&self) -> u64 { self.total_persona_persist.load(Ordering::Relaxed) }
    pub fn total_fragmentation(&self) -> u64 { self.total_fragmentation.load(Ordering::Relaxed) }
    pub fn total_trust_exploit(&self) -> u64 { self.total_trust_exploit.load(Ordering::Relaxed) }
    pub fn active_sessions(&self) -> usize { self.sessions.read().len() }
    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
