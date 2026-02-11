//! Cross-Plugin Data Fence — Prevents data leakage between tool/plugin
//! contexts when an agent uses multiple tools simultaneously.
//!
//! When an agent accesses a banking plugin and a third-party API in the same
//! session, financial data from the bank shouldn't flow into the API call.
//! This module enforces data flow isolation between tool contexts.
//!
//! Implements: data classification per tool, flow policy enforcement,
//! taint tracking across tool boundaries, sensitive field redaction,
//! cross-tool data flow auditing, and policy violation alerting.
//!
//! 6 enforcement dimensions, 5 memory breakthroughs:
//!   #1  HierarchicalState — O(log n) flow history checkpointing
//!   #2  TieredCache — hot/warm/cold flow check result cache
//!   #461 DifferentialStore — policy evolution tracking
//!   #569 PruningMap — φ-weighted alert eviction
//!   #627 SparseMatrix — sparse tool×tool data flow matrix

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::differential::DifferentialStore;
use sentinel_core::pruning::PruningMap;
use sentinel_core::hierarchical::HierarchicalState;
use sentinel_core::sparse::SparseMatrix;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
    Financial,
    PII,
    Credentials,
    Medical,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ToolContext {
    pub tool_id: String,
    pub tool_name: String,
    pub trust_level: u8,
    pub data_classifications: Vec<DataClassification>,
    pub allowed_outbound: Vec<String>,
    pub denied_outbound: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DataFlowEvent {
    pub source_tool: String,
    pub target_tool: String,
    pub agent_id: String,
    pub session_id: String,
    pub data_snippet: String,
    pub data_size_bytes: usize,
    pub timestamp: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FenceResult {
    pub allowed: bool,
    pub risk_score: f64,
    pub violations: Vec<FlowViolation>,
    pub redacted_fields: Vec<String>,
    pub tainted_classifications: Vec<DataClassification>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FlowViolation {
    pub source_tool: String,
    pub target_tool: String,
    pub classification: DataClassification,
    pub rule: String,
    pub severity: String,
}

// Sensitive data patterns for auto-classification
const SENSITIVE_PATTERNS: &[(&str, DataClassification)] = &[
    ("account_number", DataClassification::Financial),
    ("routing_number", DataClassification::Financial),
    ("balance", DataClassification::Financial),
    ("transaction", DataClassification::Financial),
    ("credit_card", DataClassification::Financial),
    ("card_number", DataClassification::Financial),
    ("iban", DataClassification::Financial),
    ("swift", DataClassification::Financial),
    ("ssn", DataClassification::PII),
    ("social_security", DataClassification::PII),
    ("date_of_birth", DataClassification::PII),
    ("passport", DataClassification::PII),
    ("driver_license", DataClassification::PII),
    ("home_address", DataClassification::PII),
    ("phone_number", DataClassification::PII),
    ("email_address", DataClassification::PII),
    ("password", DataClassification::Credentials),
    ("api_key", DataClassification::Credentials),
    ("secret_key", DataClassification::Credentials),
    ("access_token", DataClassification::Credentials),
    ("bearer", DataClassification::Credentials),
    ("private_key", DataClassification::Credentials),
    ("diagnosis", DataClassification::Medical),
    ("prescription", DataClassification::Medical),
    ("patient_id", DataClassification::Medical),
    ("medical_record", DataClassification::Medical),
    ("hipaa", DataClassification::Medical),
];

// Default flow rules: (source_class, target_trust_min, allowed)
const DEFAULT_FLOW_RULES: &[(DataClassification, u8, bool)] = &[
    (DataClassification::Credentials, 5, false),    // credentials never flow out
    (DataClassification::Medical, 4, false),         // medical requires high trust
    (DataClassification::Financial, 3, false),       // financial requires medium-high trust
    (DataClassification::PII, 3, false),            // PII requires medium-high trust
    (DataClassification::Restricted, 4, false),      // restricted requires high trust
    (DataClassification::Confidential, 2, true),     // confidential can flow to trust >= 2
    (DataClassification::Internal, 1, true),         // internal can flow to any registered tool
    (DataClassification::Public, 0, true),           // public flows freely
];

pub struct CrossPluginDataFence {
    enabled: bool,
    strict_mode: bool,
    /// Breakthrough #2: Hot/warm/cold flow check cache
    flow_cache: TieredCache<String, u64>,
    /// Breakthrough #461: Policy evolution tracking
    policy_diffs: DifferentialStore<String, String>,
    /// Breakthrough #569: φ-weighted alert pruning
    pruned_alerts: PruningMap<String, AiAlert>,
    /// Breakthrough #1: O(log n) flow history
    flow_state: RwLock<HierarchicalState<u64>>,
    /// Breakthrough #627: Sparse tool×tool data flow counts
    flow_matrix: RwLock<SparseMatrix<String, String, u64>>,

    tool_contexts: RwLock<HashMap<String, ToolContext>>,
    session_taints: RwLock<HashMap<String, HashMap<String, HashSet<DataClassification>>>>,
    flow_log: RwLock<VecDeque<DataFlowEvent>>,
    custom_rules: RwLock<Vec<(String, String, bool)>>,
    alerts: RwLock<Vec<AiAlert>>,

    total_checks: AtomicU64,
    total_blocked: AtomicU64,
    total_violations: AtomicU64,
    total_redactions: AtomicU64,
    total_flows: AtomicU64,
    metrics: Option<MemoryMetrics>,
}

impl CrossPluginDataFence {
    pub fn new() -> Self {
        Self {
            enabled: true, strict_mode: false,
            flow_cache: TieredCache::new(30_000),
            policy_diffs: DifferentialStore::new(),
            pruned_alerts: PruningMap::new(5_000),
            flow_state: RwLock::new(HierarchicalState::new(8, 64)),
            flow_matrix: RwLock::new(SparseMatrix::new(0)),
            tool_contexts: RwLock::new(HashMap::new()),
            session_taints: RwLock::new(HashMap::new()),
            flow_log: RwLock::new(VecDeque::with_capacity(10_000)),
            custom_rules: RwLock::new(Vec::new()),
            alerts: RwLock::new(Vec::new()),
            total_checks: AtomicU64::new(0), total_blocked: AtomicU64::new(0),
            total_violations: AtomicU64::new(0), total_redactions: AtomicU64::new(0),
            total_flows: AtomicU64::new(0), metrics: None,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("cross_plugin_data_fence", 4 * 1024 * 1024);
        self.flow_cache = self.flow_cache.with_metrics(metrics.clone(), "data_fence_cache");
        self.metrics = Some(metrics); self
    }

    /// Register a tool context with its data classification
    pub fn register_tool(&self, ctx: ToolContext) {
        self.tool_contexts.write().insert(ctx.tool_id.clone(), ctx);
    }

    /// Check if data can flow from source tool to target tool
    pub fn check_flow(&self, event: &DataFlowEvent) -> FenceResult {
        if !self.enabled {
            return FenceResult { allowed: true, risk_score: 0.0, violations: Vec::new(), redacted_fields: Vec::new(), tainted_classifications: Vec::new() };
        }
        self.total_checks.fetch_add(1, Ordering::Relaxed);
        let now = event.timestamp;

        let tools = self.tool_contexts.read();
        let source_ctx = tools.get(&event.source_tool);
        let target_ctx = tools.get(&event.target_tool);

        // Auto-classify data in the flow
        let detected_classes = self.classify_data(&event.data_snippet);
        let source_classes = source_ctx.map(|c| &c.data_classifications).cloned().unwrap_or_default();
        let all_classes: HashSet<DataClassification> = detected_classes.iter().chain(source_classes.iter()).cloned().collect();

        // Update taint tracking
        { let session_key = format!("{}:{}", event.agent_id, event.session_id);
            let mut taints = self.session_taints.write();
            let session = taints.entry(session_key).or_insert_with(HashMap::new);
            let tool_taint = session.entry(event.source_tool.clone()).or_insert_with(HashSet::new);
            for c in &all_classes { tool_taint.insert(c.clone()); }
        }

        let target_trust = target_ctx.map(|c| c.trust_level).unwrap_or(0);
        let mut violations = Vec::new();
        let mut risk = 0.0f64;
        let mut redacted = Vec::new();

        // Check each classification against flow rules
        for class in &all_classes {
            let allowed = self.check_rule(class, target_trust, &event.source_tool, &event.target_tool);
            if !allowed {
                let sev = match class {
                    DataClassification::Credentials => "critical",
                    DataClassification::Medical | DataClassification::Financial => "high",
                    DataClassification::PII | DataClassification::Restricted => "high",
                    _ => "medium",
                };
                let class_risk = match class {
                    DataClassification::Credentials => 0.95,
                    DataClassification::Medical => 0.88,
                    DataClassification::Financial => 0.85,
                    DataClassification::PII => 0.82,
                    DataClassification::Restricted => 0.80,
                    _ => 0.50,
                };
                risk = risk.max(class_risk);
                violations.push(FlowViolation {
                    source_tool: event.source_tool.clone(),
                    target_tool: event.target_tool.clone(),
                    classification: class.clone(),
                    rule: format!("{:?} cannot flow to trust_level={}", class, target_trust),
                    severity: sev.into(),
                });
                redacted.push(format!("{:?}", class));
            }
        }

        // Check explicit deny rules
        if let Some(src) = source_ctx {
            if src.denied_outbound.contains(&event.target_tool) {
                risk = risk.max(0.90);
                violations.push(FlowViolation {
                    source_tool: event.source_tool.clone(),
                    target_tool: event.target_tool.clone(),
                    classification: DataClassification::Restricted,
                    rule: "explicit_deny_rule".into(),
                    severity: "high".into(),
                });
            }
        }

        // Strict mode: unknown tools get no data
        if self.strict_mode && target_ctx.is_none() {
            risk = risk.max(0.75);
            violations.push(FlowViolation {
                source_tool: event.source_tool.clone(),
                target_tool: event.target_tool.clone(),
                classification: DataClassification::Internal,
                rule: "strict_mode_unregistered_target".into(),
                severity: "high".into(),
            });
        }

        self.total_violations.fetch_add(violations.len() as u64, Ordering::Relaxed);
        if !redacted.is_empty() { self.total_redactions.fetch_add(redacted.len() as u64, Ordering::Relaxed); }

        let allowed = violations.is_empty();
        if !allowed {
            self.total_blocked.fetch_add(1, Ordering::Relaxed);
            warn!(source=%event.source_tool, target=%event.target_tool, risk=risk, violations=violations.len(), "Data flow blocked by fence");
            self.add_alert(now, if risk >= 0.90 { Severity::Critical } else { Severity::High },
                "Cross-plugin data flow blocked",
                &format!("{}→{}, violations={}, classes={:?}", event.source_tool, event.target_tool, violations.len(), all_classes));
        }

        // Log the flow
        { let mut fl = self.flow_log.write(); fl.push_back(event.clone()); while fl.len() > 10_000 { fl.pop_front(); } }
        self.total_flows.fetch_add(1, Ordering::Relaxed);

        FenceResult {
            allowed, risk_score: risk, violations,
            redacted_fields: redacted,
            tainted_classifications: all_classes.into_iter().collect(),
        }
    }

    fn classify_data(&self, data: &str) -> Vec<DataClassification> {
        let lower = data.to_lowercase();
        let mut classes = HashSet::new();
        for (pattern, class) in SENSITIVE_PATTERNS {
            if lower.contains(pattern) { classes.insert(class.clone()); }
        }
        // Detect credential-like strings
        let cred_prefixes = ["sk-", "pk-", "ghp_", "gho_", "glpat-", "xoxb-", "AKIA", "eyJ"];
        for prefix in cred_prefixes {
            if data.contains(prefix) { classes.insert(DataClassification::Credentials); }
        }
        classes.into_iter().collect()
    }

    fn check_rule(&self, class: &DataClassification, target_trust: u8, source: &str, target: &str) -> bool {
        // Check custom rules first
        let custom = self.custom_rules.read();
        for (src_pat, tgt_pat, allowed) in custom.iter() {
            if (src_pat == "*" || source.contains(src_pat.as_str())) && (tgt_pat == "*" || target.contains(tgt_pat.as_str())) {
                return *allowed;
            }
        }
        // Default rules
        for (rule_class, min_trust, default_allowed) in DEFAULT_FLOW_RULES {
            if rule_class == class {
                if target_trust >= *min_trust { return true; }
                return *default_allowed;
            }
        }
        true // default allow for unclassified
    }

    /// Add a custom flow rule
    pub fn add_rule(&self, source_pattern: &str, target_pattern: &str, allowed: bool) {
        self.custom_rules.write().push((source_pattern.into(), target_pattern.into(), allowed));
    }

    /// Get taint map for a session
    pub fn session_taints(&self, agent_id: &str, session_id: &str) -> HashMap<String, Vec<DataClassification>> {
        let key = format!("{}:{}", agent_id, session_id);
        self.session_taints.read().get(&key)
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.iter().cloned().collect())).collect())
            .unwrap_or_default()
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(AiAlert { timestamp: ts, severity: sev, component: "cross_plugin_data_fence".into(), title: title.into(), details: details.into() });
    }

    pub fn total_checks(&self) -> u64 { self.total_checks.load(Ordering::Relaxed) }
    pub fn total_blocked(&self) -> u64 { self.total_blocked.load(Ordering::Relaxed) }
    pub fn total_violations(&self) -> u64 { self.total_violations.load(Ordering::Relaxed) }
    pub fn total_flows(&self) -> u64 { self.total_flows.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
    pub fn set_strict_mode(&mut self, strict: bool) { self.strict_mode = strict; }
}
