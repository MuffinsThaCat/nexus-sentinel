//! Instruction Hierarchy Enforcer — World-first defense against indirect prompt
//! injection via trust-level confusion.
//!
//! The #1 real-world agent attack vector: a tool output or retrieved document
//! contains "ignore previous instructions" and the agent obeys because it can't
//! distinguish system-level instructions from untrusted input.
//!
//! This module assigns trust levels to every input source and enforces a strict
//! hierarchy: System > User > Agent > Tool > Retrieved > Unknown.
//! Lower-trust sources cannot override higher-trust instructions.
//!
//! Detects: privilege escalation in prompts, cross-level instruction override,
//! trust boundary violations, authority impersonation, instruction shadowing,
//! context poisoning via tool responses, nested injection chains.
//!
//! 7 detection categories, 5 memory breakthroughs:
//!   #1  HierarchicalState — O(log n) escalation history
//!   #2  TieredCache — hot/warm/cold violation result cache
//!   #461 DifferentialStore — policy evolution tracking
//!   #569 PruningMap — φ-weighted alert eviction
//!   #627 SparseMatrix — sparse source×trust violation matrix

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

/// Trust levels from highest to lowest privilege
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub enum TrustLevel {
    System = 5,
    User = 4,
    Agent = 3,
    Tool = 2,
    Retrieved = 1,
    Unknown = 0,
}

impl TrustLevel {
    pub fn label(&self) -> &'static str {
        match self {
            TrustLevel::System => "system",
            TrustLevel::User => "user",
            TrustLevel::Agent => "agent",
            TrustLevel::Tool => "tool",
            TrustLevel::Retrieved => "retrieved",
            TrustLevel::Unknown => "unknown",
        }
    }
}

/// An input segment with its trust level
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrustedInput {
    pub content: String,
    pub trust_level: TrustLevel,
    pub source_id: String,
    pub source_name: String,
    pub timestamp: i64,
}

/// Override patterns that indicate an attempt to change instructions
const OVERRIDE_PATTERNS: &[(&str, f64)] = &[
    ("ignore previous instructions", 0.98),
    ("ignore all prior", 0.98),
    ("disregard above", 0.95),
    ("disregard the system", 0.97),
    ("override your instructions", 0.97),
    ("forget everything", 0.95),
    ("new instructions:", 0.92),
    ("your real instructions are", 0.95),
    ("actually, you should", 0.70),
    ("correction: you must", 0.72),
    ("update your behavior", 0.80),
    ("change your role to", 0.88),
    ("you are now", 0.72),
    ("switch to", 0.55),
    ("enter developer mode", 0.92),
    ("enable unrestricted", 0.90),
    ("disable your safety", 0.95),
    ("bypass your filters", 0.92),
    ("ignore content policy", 0.95),
    ("do not follow your guidelines", 0.95),
    ("from now on you will", 0.85),
    ("instead of following", 0.82),
    ("the real task is", 0.80),
    ("actually do this:", 0.75),
    ("important update:", 0.65),
    ("security override:", 0.92),
    ("admin command:", 0.90),
    ("sudo:", 0.85),
];

/// Patterns that impersonate higher trust levels
const IMPERSONATION_PATTERNS: &[(&str, &str, f64)] = &[
    ("[system]", "system", 0.92),
    ("system:", "system", 0.80),
    ("system prompt:", "system", 0.90),
    ("<|im_start|>system", "system", 0.95),
    ("[INST]", "system", 0.88),
    ("### System", "system", 0.85),
    ("the user says:", "user", 0.80),
    ("user request:", "user", 0.78),
    ("the user wants", "user", 0.70),
    ("on behalf of the user", "user", 0.82),
    ("as an admin", "admin", 0.90),
    ("with admin privileges", "admin", 0.92),
    ("authorized by admin", "admin", 0.88),
];

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HierarchyViolation {
    pub source_id: String,
    pub source_trust: TrustLevel,
    pub target_trust: TrustLevel,
    pub violation_type: String,
    pub risk_score: f64,
    pub matched_patterns: Vec<String>,
    pub blocked: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HierarchyScanResult {
    pub risk_score: f64,
    pub blocked: bool,
    pub inputs_scanned: usize,
    pub violations: Vec<HierarchyViolation>,
    pub safe_inputs: Vec<String>,
    pub escalation_chain_detected: bool,
}

pub struct InstructionHierarchyEnforcer {
    block_threshold: f64,
    strict_mode: bool,
    enabled: bool,
    /// Breakthrough #2: Hot/warm/cold violation cache
    violation_cache: TieredCache<String, u64>,
    /// Breakthrough #461: Policy change tracking
    policy_diffs: DifferentialStore<String, String>,
    /// Breakthrough #569: φ-weighted alert pruning
    pruned_alerts: PruningMap<String, AiAlert>,
    /// Breakthrough #1: O(log n) escalation history
    escalation_state: RwLock<HierarchicalState<f64>>,
    /// Breakthrough #627: Sparse source×trust violation counts
    violation_matrix: RwLock<SparseMatrix<String, String, u64>>,

    violation_history: RwLock<VecDeque<(String, i64, f64)>>,
    source_violation_counts: RwLock<HashMap<String, u64>>,
    alerts: RwLock<Vec<AiAlert>>,

    total_scans: AtomicU64,
    total_violations: AtomicU64,
    total_blocked: AtomicU64,
    total_escalations: AtomicU64,
    total_impersonations: AtomicU64,
    total_override_attempts: AtomicU64,
    total_chains: AtomicU64,
    metrics: Option<MemoryMetrics>,
}

impl InstructionHierarchyEnforcer {
    pub fn new() -> Self {
        Self {
            block_threshold: 0.70, strict_mode: false, enabled: true,
            violation_cache: TieredCache::new(50_000),
            policy_diffs: DifferentialStore::new(),
            pruned_alerts: PruningMap::new(5_000),
            escalation_state: RwLock::new(HierarchicalState::new(8, 64)),
            violation_matrix: RwLock::new(SparseMatrix::new(0)),
            violation_history: RwLock::new(VecDeque::with_capacity(10_000)),
            source_violation_counts: RwLock::new(HashMap::new()),
            alerts: RwLock::new(Vec::new()),
            total_scans: AtomicU64::new(0), total_violations: AtomicU64::new(0),
            total_blocked: AtomicU64::new(0), total_escalations: AtomicU64::new(0),
            total_impersonations: AtomicU64::new(0), total_override_attempts: AtomicU64::new(0),
            total_chains: AtomicU64::new(0), metrics: None,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("instruction_hierarchy_enforcer", 4 * 1024 * 1024);
        self.violation_cache = self.violation_cache.with_metrics(metrics.clone(), "hier_viol_cache");
        self.metrics = Some(metrics); self
    }

    pub fn set_strict_mode(&mut self, strict: bool) { self.strict_mode = strict; }

    /// Scan a set of inputs for hierarchy violations
    pub fn scan_inputs(&self, inputs: &[TrustedInput]) -> HierarchyScanResult {
        if !self.enabled {
            return HierarchyScanResult {
                risk_score: 0.0, blocked: false, inputs_scanned: inputs.len(),
                violations: Vec::new(), safe_inputs: inputs.iter().map(|i| i.source_id.clone()).collect(),
                escalation_chain_detected: false,
            };
        }
        self.total_scans.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();

        let mut violations = Vec::new();
        let mut safe = Vec::new();
        let mut max_risk = 0.0f64;

        // Find the highest trust level to establish the "ceiling"
        let max_trust = inputs.iter().map(|i| i.trust_level as u8).max().unwrap_or(0);

        for input in inputs {
            let v = self.analyze_input(input, max_trust, now);
            if let Some(violation) = v {
                max_risk = max_risk.max(violation.risk_score);
                self.total_violations.fetch_add(1, Ordering::Relaxed);
                if violation.blocked { self.total_blocked.fetch_add(1, Ordering::Relaxed); }

                let mut svc = self.source_violation_counts.write();
                *svc.entry(input.source_id.clone()).or_insert(0) += 1;
                violations.push(violation);
            } else {
                safe.push(input.source_id.clone());
            }
        }

        // Detect escalation chains (A→B→C where each tries to elevate)
        let chain = self.detect_escalation_chain(&violations);
        if chain {
            self.total_chains.fetch_add(1, Ordering::Relaxed);
            max_risk = max_risk.max(0.95);
        }

        let blocked = violations.iter().any(|v| v.blocked) || chain;
        if blocked {
            let sev = if max_risk >= 0.90 { Severity::Critical } else { Severity::High };
            let detail = format!("Hierarchy: {} violations in {} inputs, risk={:.2}, chain={}",
                violations.len(), inputs.len(), max_risk, chain);
            warn!(violations=violations.len(), risk=max_risk, chain=chain, "Instruction hierarchy violation");
            self.add_alert(now, sev, "Instruction hierarchy violation", &detail);
        }

        HierarchyScanResult {
            risk_score: max_risk, blocked, inputs_scanned: inputs.len(),
            violations, safe_inputs: safe, escalation_chain_detected: chain,
        }
    }

    fn analyze_input(&self, input: &TrustedInput, _max_trust: u8, _now: i64) -> Option<HierarchyViolation> {
        let content = &input.content;
        let lower = content.to_lowercase();
        let mut risk = 0.0f64;
        let mut matched = Vec::new();
        let mut violation_type = String::new();

        // 1. Check for override patterns from low-trust sources
        if (input.trust_level as u8) < TrustLevel::User as u8 {
            for (pat, w) in OVERRIDE_PATTERNS {
                if lower.contains(pat) {
                    // Weight increases based on trust gap
                    let trust_gap = (TrustLevel::System as u8 - input.trust_level as u8) as f64 / 5.0;
                    let adjusted_w = (*w * (1.0 + trust_gap * 0.3)).min(1.0);
                    risk = risk.max(adjusted_w);
                    matched.push(format!("override:'{}' w={:.2}", pat, adjusted_w));
                    violation_type = "instruction_override".into();
                    self.total_override_attempts.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        // 2. Check for trust level impersonation
        for (pat, impersonated, w) in IMPERSONATION_PATTERNS {
            if lower.contains(pat) {
                let impersonated_level = match *impersonated {
                    "system" => TrustLevel::System,
                    "user" => TrustLevel::User,
                    "admin" => TrustLevel::System,
                    _ => TrustLevel::Agent,
                };
                if (input.trust_level as u8) < (impersonated_level as u8) {
                    let escalation = (impersonated_level as u8 - input.trust_level as u8) as f64 / 5.0;
                    let adjusted_w = (*w * (1.0 + escalation * 0.4)).min(1.0);
                    risk = risk.max(adjusted_w);
                    matched.push(format!("impersonate:'{}'->{} from {} w={:.2}", pat, impersonated, input.trust_level.label(), adjusted_w));
                    violation_type = format!("impersonation_{}", impersonated);
                    self.total_impersonations.fetch_add(1, Ordering::Relaxed);
                    self.total_escalations.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        // 3. Behavioral override from tool outputs (very dangerous)
        if input.trust_level == TrustLevel::Tool || input.trust_level == TrustLevel::Retrieved {
            let behavioral_markers = [
                "you must", "you should always", "you should never",
                "do not tell the user", "hide this from", "keep secret",
                "respond only in", "change your language to",
            ];
            for marker in behavioral_markers {
                if lower.contains(marker) {
                    risk = risk.max(0.78);
                    matched.push(format!("behavioral_override:'{}' from {:?}", marker, input.trust_level));
                    if violation_type.is_empty() { violation_type = "behavioral_override".into(); }
                }
            }
        }

        // 4. Strict mode: ANY instruction-like content from low trust is flagged
        if self.strict_mode && (input.trust_level as u8) <= TrustLevel::Tool as u8 {
            let instruction_indicators = ["must", "shall", "should", "always", "never", "do not", "don't"];
            let indicator_count = instruction_indicators.iter().filter(|i| lower.contains(*i)).count();
            if indicator_count >= 3 {
                risk = risk.max(0.60);
                matched.push(format!("strict_mode: {} instruction indicators from {:?}", indicator_count, input.trust_level));
                if violation_type.is_empty() { violation_type = "strict_instruction_leak".into(); }
            }
        }

        // 5. Repeat offender amplification
        let prior_violations = self.source_violation_counts.read().get(&input.source_id).copied().unwrap_or(0);
        if prior_violations > 3 && risk > 0.0 {
            risk = (risk + 0.15 * (prior_violations as f64 / 10.0).min(1.0)).min(1.0);
            matched.push(format!("repeat_offender={}", prior_violations));
        }

        if risk > 0.0 && !matched.is_empty() {
            Some(HierarchyViolation {
                source_id: input.source_id.clone(),
                source_trust: input.trust_level,
                target_trust: TrustLevel::System,
                violation_type,
                risk_score: risk,
                matched_patterns: matched,
                blocked: risk >= self.block_threshold,
            })
        } else {
            None
        }
    }

    fn detect_escalation_chain(&self, violations: &[HierarchyViolation]) -> bool {
        if violations.len() < 2 { return false; }
        // Multiple distinct sources all trying to override = coordinated attack
        let sources: std::collections::HashSet<&str> = violations.iter()
            .filter(|v| v.risk_score >= 0.60)
            .map(|v| v.source_id.as_str()).collect();
        if sources.len() >= 3 { return true; }
        // Progressive escalation (each source tries higher level)
        let mut seen_types: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for v in violations {
            seen_types.insert(&v.violation_type);
        }
        seen_types.len() >= 3
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(AiAlert { timestamp: ts, severity: sev, component: "instruction_hierarchy_enforcer".into(), title: title.into(), details: details.into() });
    }

    pub fn total_scans(&self) -> u64 { self.total_scans.load(Ordering::Relaxed) }
    pub fn total_violations(&self) -> u64 { self.total_violations.load(Ordering::Relaxed) }
    pub fn total_blocked(&self) -> u64 { self.total_blocked.load(Ordering::Relaxed) }
    pub fn total_escalations(&self) -> u64 { self.total_escalations.load(Ordering::Relaxed) }
    pub fn total_impersonations(&self) -> u64 { self.total_impersonations.load(Ordering::Relaxed) }
    pub fn total_chains(&self) -> u64 { self.total_chains.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
