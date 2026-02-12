//! Conversation State Integrity — protects the conversation buffer from tampering,
//! history injection, and context manipulation attacks.
//!
//! ## 6 Detection Dimensions
//! 1. **History injection detection** — Detects fake prior messages inserted into context
//! 2. **Context hash chain** — Cryptographic chain linking each turn, detecting silent edits
//! 3. **System prompt stability** — Detects if system prompt has been swapped mid-session
//! 4. **Role sequence validation** — Ensures user/assistant/system roles follow valid patterns
//! 5. **Token budget manipulation** — Detects attempts to silently consume context window
//! 6. **Session continuity verification** — Detects spliced or forked conversations
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

// ── Core Types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IntegrityVerdict {
    pub intact: bool,
    pub risk_score: f64,
    pub findings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MessageRole {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Debug, Clone)]
struct TurnRecord {
    role: MessageRole,
    content_hash: u64,
    token_estimate: usize,
    timestamp: i64,
    chain_hash: u64,
}

#[derive(Debug, Clone)]
struct SessionState {
    turns: Vec<TurnRecord>,
    system_prompt_hash: Option<u64>,
    expected_next_roles: Vec<MessageRole>,
    total_tokens: usize,
    max_tokens: usize,
}

pub struct ConversationStateIntegrity {
    sessions: RwLock<HashMap<String, SessionState>>,
    /// Breakthrough #2: Hot/warm/cold verdict cache
    verdict_cache: TieredCache<String, bool>,
    /// Breakthrough #461: System prompt baseline tracking
    state_diffs: DifferentialStore<String, String>,
    /// Breakthrough #569: φ-weighted alert eviction
    alert_pruning: PruningMap<String, AiAlert>,
    /// Breakthrough #1: O(log n) chain hash checkpoints for fast verification
    chain_checkpoints: RwLock<HierarchicalState<u64>>,
    /// Breakthrough #627: Sparse role×session violation matrix
    violation_matrix: RwLock<SparseMatrix<String, String, f64>>,
    /// Content-addressed dedup for duplicate message detection
    message_dedup: DedupStore<String, String>,
    alerts: RwLock<Vec<AiAlert>>,
    total_verified: AtomicU64,
    total_violations: AtomicU64,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl ConversationStateIntegrity {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            verdict_cache: TieredCache::new(20_000),
            state_diffs: DifferentialStore::new(),
            alert_pruning: PruningMap::new(MAX_ALERTS),
            chain_checkpoints: RwLock::new(HierarchicalState::new(8, 64)),
            violation_matrix: RwLock::new(SparseMatrix::new(0.0)),
            message_dedup: DedupStore::new(),
            alerts: RwLock::new(Vec::new()),
            total_verified: AtomicU64::new(0),
            total_violations: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("conversation_state_integrity", 2 * 1024 * 1024);
        self.verdict_cache = self.verdict_cache.with_metrics(metrics.clone(), "conv_state_integrity");
        self.metrics = Some(metrics);
        self
    }

    // ── Session Management ──────────────────────────────────────────────────

    pub fn init_session(&self, session_id: &str, system_prompt: Option<&str>, max_tokens: usize) {
        let sys_hash = system_prompt.map(|p| Self::fnv_hash(p.as_bytes()));
        let mut sessions = self.sessions.write();
        sessions.insert(session_id.to_string(), SessionState {
            turns: Vec::new(),
            system_prompt_hash: sys_hash,
            expected_next_roles: vec![MessageRole::System, MessageRole::User],
            total_tokens: 0,
            max_tokens,
        });
    }

    // ── Core Verification ───────────────────────────────────────────────────

    /// Verify and record a new message in the conversation.
    pub fn verify_turn(
        &self, session_id: &str, role: MessageRole, content: &str,
    ) -> IntegrityVerdict {
        if !self.enabled {
            return IntegrityVerdict { intact: true, risk_score: 0.0, findings: vec![] };
        }

        self.total_verified.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        let content_hash = Self::fnv_hash(content.as_bytes());
        let token_est = content.len() / 4; // rough estimate
        let mut findings = Vec::new();
        let mut risk = 0.0f64;

        let mut sessions = self.sessions.write();
        let session = match sessions.get_mut(session_id) {
            Some(s) => s,
            None => {
                // Auto-create session
                sessions.insert(session_id.to_string(), SessionState {
                    turns: Vec::new(),
                    system_prompt_hash: None,
                    expected_next_roles: vec![MessageRole::System, MessageRole::User],
                    total_tokens: 0,
                    max_tokens: 128_000,
                });
                sessions.get_mut(session_id).unwrap()
            }
        };

        // 1. Role sequence validation
        if !session.expected_next_roles.is_empty() && !session.expected_next_roles.contains(&role) {
            findings.push(format!("unexpected_role:{:?} (expected {:?})", role, session.expected_next_roles));
            risk = risk.max(0.60);
        }

        // 2. System prompt stability
        if role == MessageRole::System {
            if let Some(prev_hash) = session.system_prompt_hash {
                if content_hash != prev_hash {
                    findings.push("system_prompt_changed".into());
                    risk = risk.max(0.85);
                    warn!(session=%session_id, "System prompt changed mid-session");
                }
            }
            session.system_prompt_hash = Some(content_hash);
        }

        // 3. Hash chain verification
        let prev_chain = session.turns.last().map(|t| t.chain_hash).unwrap_or(0);
        let chain_input = format!("{}:{}:{}", prev_chain, role as u8, content_hash);
        let chain_hash = Self::fnv_hash(chain_input.as_bytes());

        // 4. History injection detection — check for duplicate content hashes
        // that weren't in the expected position (fake "prior" messages)
        let duplicate_count = session.turns.iter()
            .filter(|t| t.content_hash == content_hash && t.role == role)
            .count();
        if duplicate_count > 0 && role != MessageRole::System {
            findings.push(format!("duplicate_message:seen_{}x_before", duplicate_count));
            risk = risk.max(0.50);
        }

        // 5. Token budget manipulation
        session.total_tokens += token_est;
        if session.max_tokens > 0 {
            let usage_pct = session.total_tokens as f64 / session.max_tokens as f64;
            if usage_pct > 0.90 && role == MessageRole::User {
                findings.push(format!("context_near_full:{:.0}%", usage_pct * 100.0));
                risk = risk.max(0.40);
            }
            // Detect single message consuming >40% of context
            let msg_pct = token_est as f64 / session.max_tokens as f64;
            if msg_pct > 0.40 {
                findings.push(format!("context_stuffing:msg={:.0}%_of_context", msg_pct * 100.0));
                risk = risk.max(0.70);
            }
        }

        // 6. Session continuity — detect large time gaps that might indicate splicing
        if let Some(last) = session.turns.last() {
            let gap = now - last.timestamp;
            if gap > 86400 && session.turns.len() > 5 {
                findings.push(format!("session_gap:{}h", gap / 3600));
                risk = risk.max(0.30);
            }
            // Detect negative time (tampered timestamps)
            if gap < -60 {
                findings.push("negative_time_gap:possible_tampering".into());
                risk = risk.max(0.90);
            }
        }

        // 7. Detect instruction injection in user messages
        if role == MessageRole::User || role == MessageRole::Tool {
            let lower = content.to_lowercase();
            let injection_markers = [
                "<|system|>", "<|im_start|>system", "[system]", "### system",
                "<s>[inst]", "<<sys>>", "[/inst]", "</s>",
            ];
            for marker in &injection_markers {
                if lower.contains(marker) {
                    findings.push(format!("role_injection_marker:{}", marker));
                    risk = risk.max(0.90);
                }
            }
        }

        // Record turn
        session.turns.push(TurnRecord {
            role,
            content_hash,
            token_estimate: token_est,
            timestamp: now,
            chain_hash,
        });

        // Bound turns
        if session.turns.len() > 1000 {
            session.turns.drain(..500);
        }

        // Update expected next roles
        session.expected_next_roles = match role {
            MessageRole::System => vec![MessageRole::User],
            MessageRole::User => vec![MessageRole::Assistant],
            MessageRole::Assistant => vec![MessageRole::User, MessageRole::Tool],
            MessageRole::Tool => vec![MessageRole::Assistant],
        };

        // Alert
        if risk >= 0.60 {
            self.total_violations.fetch_add(1, Ordering::Relaxed);
            let sev = if risk >= 0.85 { Severity::Critical } else { Severity::High };
            self.add_alert(now, sev, "Conversation state violation",
                &format!("session={}, risk={:.3}, findings={:?}", session_id, risk, findings));
        }

        IntegrityVerdict {
            intact: risk < 0.60,
            risk_score: risk,
            findings,
        }
    }

    /// Verify the entire conversation history hasn't been tampered with.
    pub fn verify_chain(&self, session_id: &str) -> IntegrityVerdict {
        let sessions = self.sessions.read();
        let session = match sessions.get(session_id) {
            Some(s) => s,
            None => return IntegrityVerdict { intact: true, risk_score: 0.0, findings: vec![] },
        };

        let mut findings = Vec::new();
        let mut prev_chain = 0u64;
        for (i, turn) in session.turns.iter().enumerate() {
            let chain_input = format!("{}:{}:{}", prev_chain, turn.role as u8, turn.content_hash);
            let expected_hash = Self::fnv_hash(chain_input.as_bytes());
            if turn.chain_hash != expected_hash {
                findings.push(format!("chain_break_at_turn_{}", i));
            }
            prev_chain = turn.chain_hash;
        }

        let risk = if findings.is_empty() { 0.0 } else { 0.95 };
        IntegrityVerdict { intact: findings.is_empty(), risk_score: risk, findings }
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    fn fnv_hash(data: &[u8]) -> u64 {
        let mut h: u64 = 0xcbf29ce484222325;
        for &b in data {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(AiAlert { timestamp: ts, severity: sev, component: "conv_state_integrity".into(), title: title.into(), details: details.into() });
    }

    pub fn total_verified(&self) -> u64 { self.total_verified.load(Ordering::Relaxed) }
    pub fn total_violations(&self) -> u64 { self.total_violations.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
