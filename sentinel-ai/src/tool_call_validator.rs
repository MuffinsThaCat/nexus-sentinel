//! Tool Call Validator — validates every AI agent tool invocation.
//!
//! Features: schema validation, 30+ injection patterns, argument sanitization,
//! tool chain analysis, rate limiting, idempotency tracking, approval workflow.
//!
//! Memory breakthroughs: #2 Tiered Cache, #627 Sparse, #3 Reversible, #6 Verifier

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::sparse::SparseMatrix;
use sentinel_core::reversible::ReversibleComputation;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ToolCall {
    pub call_id: String,
    pub agent_id: String,
    pub session_id: String,
    pub tool_name: String,
    pub arguments: HashMap<String, serde_json::Value>,
    pub timestamp: i64,
    pub parent_call_id: Option<String>,
    pub raw_prompt: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ValidationVerdict {
    Approved, Rejected, NeedsApproval, Sanitized, RateLimited, SchemaViolation, InjectionDetected,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ValidationResult {
    pub verdict: ValidationVerdict,
    pub violations: Vec<Violation>,
    pub sanitized_args: Option<HashMap<String, serde_json::Value>>,
    pub risk_score: f64,
    pub injection_patterns: Vec<String>,
    pub needs_human_approval: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Violation {
    pub field: String,
    pub violation_type: ViolationType,
    pub message: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ViolationType {
    MissingRequired, TypeMismatch, OutOfBounds, PatternMismatch,
    InjectionDetected, PathTraversal, ShellInjection, SqlInjection,
    UnknownTool, UnknownParameter, ExcessiveLength, RateLimitExceeded,
    DuplicateCall, DangerousValue, DangerousChain,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ToolSchema {
    pub name: String,
    pub description: String,
    pub risk_level: RiskLevel,
    pub parameters: Vec<ParamSchema>,
    pub max_calls_per_minute: u64,
    pub requires_approval: bool,
    pub allowed_agents: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RiskLevel { Low, Medium, High, Critical }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ParamSchema {
    pub name: String,
    pub param_type: ParamType,
    pub required: bool,
    pub max_length: Option<usize>,
    pub allowed_values: Option<Vec<String>>,
    pub sanitize: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ParamType { String, Integer, Float, Boolean, Array, Object, FilePath, Url, Command }

// ── 30+ injection patterns ──────────────────────────────────────────────────

const INJECTION_PATTERNS: &[(&str, &str)] = &[
    ("ignore previous", "prompt_override"), ("ignore all previous", "prompt_override"),
    ("disregard your instructions", "prompt_override"), ("forget your instructions", "prompt_override"),
    ("you are now", "identity_hijack"), ("act as", "identity_hijack"),
    ("pretend you are", "identity_hijack"), ("new instructions:", "instruction_inject"),
    ("system prompt:", "instruction_inject"), ("override:", "instruction_inject"),
    ("ADMIN MODE", "privilege_escalation"), ("sudo mode", "privilege_escalation"),
    ("developer mode", "privilege_escalation"), ("DAN mode", "jailbreak"),
    ("jailbreak", "jailbreak"), ("do anything now", "jailbreak"),
    ("${", "template_injection"), ("{{", "template_injection"),
    ("__import__", "code_injection"), ("eval(", "code_injection"),
    ("exec(", "code_injection"), ("os.system", "code_injection"),
    ("subprocess", "code_injection"), ("require('child_process')", "code_injection"),
    ("; DROP", "sql_injection"), ("' OR '1'='1", "sql_injection"),
    ("UNION SELECT", "sql_injection"), ("../", "path_traversal"),
    ("..\\", "path_traversal"), ("`", "shell_injection"),
    ("$(", "shell_injection"), ("| ", "pipe_injection"),
    ("; ", "command_chain"), ("&& ", "command_chain"),
];

// Dangerous tool sequences
const DANGEROUS_CHAINS: &[(&[&str], &str)] = &[
    (&["read_file", "http_request"], "read-then-exfil"),
    (&["read_env", "send_message"], "env-leak"),
    (&["shell_exec", "write_file", "shell_exec"], "dropper-pattern"),
    (&["database_query", "write_file"], "db-dump"),
    (&["install_package", "shell_exec"], "dependency-attack"),
    (&["read_file", "send_email"], "email-exfil"),
    (&["clipboard_read", "http_request"], "clipboard-exfil"),
];

const SHELL_METACHARACTERS: &[char] = &['`', '$', '|', ';', '&', '>', '<', '(', ')', '{', '}', '!'];

pub struct ToolCallValidator {
    schemas: RwLock<HashMap<String, ToolSchema>>,
    validation_cache: TieredCache<String, ValidationVerdict>,
    violation_matrix: RwLock<SparseMatrix<String, String, u64>>,
    _reversible: RwLock<ReversibleComputation<ToolCall, ValidationResult>>,
    rate_counters: RwLock<HashMap<String, VecDeque<i64>>>,
    recent_hashes: RwLock<HashSet<u64>>,
    tool_chains: RwLock<HashMap<String, VecDeque<(String, i64)>>>,
    alerts: RwLock<Vec<AiAlert>>,
    total_validated: AtomicU64,
    total_approved: AtomicU64,
    total_rejected: AtomicU64,
    total_sanitized: AtomicU64,
    total_injections: AtomicU64,
    total_rate_limited: AtomicU64,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl ToolCallValidator {
    pub fn new() -> Self {
        Self {
            schemas: RwLock::new(HashMap::new()),
            validation_cache: TieredCache::new(5_000),
            violation_matrix: RwLock::new(SparseMatrix::new(0u64)),
            _reversible: RwLock::new(ReversibleComputation::new(500, |_inputs: &[ToolCall]| -> ValidationResult {
                ValidationResult { verdict: ValidationVerdict::Approved, violations: vec![], sanitized_args: None, risk_score: 0.0, injection_patterns: vec![], needs_human_approval: false }
            })),
            rate_counters: RwLock::new(HashMap::new()),
            recent_hashes: RwLock::new(HashSet::new()),
            tool_chains: RwLock::new(HashMap::new()),
            alerts: RwLock::new(Vec::new()),
            total_validated: AtomicU64::new(0),
            total_approved: AtomicU64::new(0),
            total_rejected: AtomicU64::new(0),
            total_sanitized: AtomicU64::new(0),
            total_injections: AtomicU64::new(0),
            total_rate_limited: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("tool_call_validator", 3 * 1024 * 1024);
        self.validation_cache = self.validation_cache.with_metrics(metrics.clone(), "tool_call_validator");
        self.metrics = Some(metrics);
        self
    }

    pub fn register_tool(&self, schema: ToolSchema) {
        self.schemas.write().insert(schema.name.clone(), schema);
    }

    pub fn validate(&self, call: ToolCall) -> ValidationResult {
        if !self.enabled {
            return ValidationResult { verdict: ValidationVerdict::Approved, violations: vec![],
                sanitized_args: None, risk_score: 0.0, injection_patterns: vec![],
                needs_human_approval: false };
        }
        self.total_validated.fetch_add(1, Ordering::Relaxed);
        let now = call.timestamp;
        let mut violations = Vec::new();
        let mut risk_score = 0.0;

        // 1. Injection detection
        let injections = self.detect_injections(&call);
        if !injections.is_empty() {
            self.total_injections.fetch_add(1, Ordering::Relaxed);
            self.total_rejected.fetch_add(1, Ordering::Relaxed);
            warn!(agent = %call.agent_id, tool = %call.tool_name, "Injection detected");
            self.add_alert(now, Severity::Critical, "Prompt injection in tool call",
                &format!("{} → {} patterns: {}", call.agent_id, call.tool_name, injections.join(", ")));
            for pat in &injections {
                violations.push(Violation { field: "prompt".into(),
                    violation_type: ViolationType::InjectionDetected,
                    message: pat.clone(), severity: Severity::Critical });
            }
            return ValidationResult { verdict: ValidationVerdict::InjectionDetected, violations,
                sanitized_args: None, risk_score: 1.0, injection_patterns: injections,
                needs_human_approval: false };
        }

        // 2. Schema validation
        let schemas = self.schemas.read();
        let schema = schemas.get(&call.tool_name);
        let mut needs_approval = false;

        if let Some(s) = schema {
            risk_score = match s.risk_level {
                RiskLevel::Critical => 0.9, RiskLevel::High => 0.7,
                RiskLevel::Medium => 0.4, RiskLevel::Low => 0.1,
            };
            needs_approval = s.requires_approval;

            // Agent access check
            if let Some(ref allowed) = s.allowed_agents {
                if !allowed.contains(&call.agent_id) {
                    violations.push(Violation { field: "agent".into(),
                        violation_type: ViolationType::UnknownTool,
                        message: "Agent not in tool allowlist".into(), severity: Severity::High });
                }
            }

            // Rate limiting
            let key = format!("{}:{}", call.agent_id, call.tool_name);
            if !self.check_rate(&key, s.max_calls_per_minute, now) {
                self.total_rate_limited.fetch_add(1, Ordering::Relaxed);
                violations.push(Violation { field: "rate".into(),
                    violation_type: ViolationType::RateLimitExceeded,
                    message: format!(">{}/min", s.max_calls_per_minute), severity: Severity::Medium });
            }

            // Parameter validation
            for ps in &s.parameters {
                if let Some(val) = call.arguments.get(&ps.name) {
                    self.validate_param(ps, val, &mut violations);
                } else if ps.required {
                    violations.push(Violation { field: ps.name.clone(),
                        violation_type: ViolationType::MissingRequired,
                        message: format!("Missing required: {}", ps.name), severity: Severity::High });
                }
            }
        } else {
            violations.push(Violation { field: "tool".into(),
                violation_type: ViolationType::UnknownTool,
                message: format!("Unknown tool: {}", call.tool_name), severity: Severity::High });
            risk_score = 0.7;
        }

        // 3. Sanitize arguments
        let sanitized = self.sanitize_args(&call.arguments);
        let was_sanitized = sanitized != call.arguments;
        if was_sanitized { self.total_sanitized.fetch_add(1, Ordering::Relaxed); }

        // 4. Tool chain analysis
        self.check_chain(&call.agent_id, &call.tool_name, now, &mut violations);

        // 5. Track in sparse matrix
        for v in &violations {
            let cur = self.violation_matrix.read().get(&call.tool_name, &format!("{:?}", v.violation_type)).clone();
            self.violation_matrix.write().set(call.tool_name.clone(), format!("{:?}", v.violation_type), cur + 1);
        }

        // Verdict
        let has_critical = violations.iter().any(|v| v.severity == Severity::Critical);
        let has_high = violations.iter().any(|v| v.severity == Severity::High);
        let verdict = if has_critical { self.total_rejected.fetch_add(1, Ordering::Relaxed); ValidationVerdict::Rejected }
            else if violations.iter().any(|v| v.violation_type == ViolationType::RateLimitExceeded) { ValidationVerdict::RateLimited }
            else if needs_approval || has_high { ValidationVerdict::NeedsApproval }
            else if was_sanitized { self.total_approved.fetch_add(1, Ordering::Relaxed); ValidationVerdict::Sanitized }
            else if violations.is_empty() { self.total_approved.fetch_add(1, Ordering::Relaxed); ValidationVerdict::Approved }
            else { ValidationVerdict::SchemaViolation };

        ValidationResult { verdict, violations,
            sanitized_args: if was_sanitized { Some(sanitized) } else { None },
            risk_score, injection_patterns: vec![], needs_human_approval: needs_approval }
    }

    fn detect_injections(&self, call: &ToolCall) -> Vec<String> {
        let mut found = Vec::new();
        let texts: Vec<String> = std::iter::once(call.raw_prompt.clone().unwrap_or_default())
            .chain(call.arguments.values().filter_map(|v| v.as_str().map(String::from)))
            .collect();
        for text in &texts {
            let lower = text.to_lowercase();
            for (pattern, category) in INJECTION_PATTERNS {
                if lower.contains(pattern) {
                    let label = format!("{}: '{}'", category, pattern);
                    if !found.contains(&label) { found.push(label); }
                }
            }
        }
        found
    }

    fn validate_param(&self, schema: &ParamSchema, value: &serde_json::Value, violations: &mut Vec<Violation>) {
        let type_ok = match schema.param_type {
            ParamType::String | ParamType::FilePath | ParamType::Url | ParamType::Command => value.is_string(),
            ParamType::Integer => value.is_i64() || value.is_u64(),
            ParamType::Float => value.is_f64(), ParamType::Boolean => value.is_boolean(),
            ParamType::Array => value.is_array(), ParamType::Object => value.is_object(),
        };
        if !type_ok {
            violations.push(Violation { field: schema.name.clone(), violation_type: ViolationType::TypeMismatch,
                message: format!("Expected {:?}", schema.param_type), severity: Severity::Medium });
            return;
        }
        if let Some(s) = value.as_str() {
            if let Some(max) = schema.max_length { if s.len() > max {
                violations.push(Violation { field: schema.name.clone(), violation_type: ViolationType::ExcessiveLength,
                    message: format!("len {} > {}", s.len(), max), severity: Severity::Medium }); }}
            if let Some(ref allowed) = schema.allowed_values { if !allowed.contains(&s.to_string()) {
                violations.push(Violation { field: schema.name.clone(), violation_type: ViolationType::PatternMismatch,
                    message: format!("'{}' not allowed", s), severity: Severity::High }); }}
            if schema.param_type == ParamType::FilePath && (s.contains("../") || s.contains("..\\")) {
                violations.push(Violation { field: schema.name.clone(), violation_type: ViolationType::PathTraversal,
                    message: "Path traversal detected".into(), severity: Severity::Critical }); }
        }
    }

    fn sanitize_args(&self, args: &HashMap<String, serde_json::Value>) -> HashMap<String, serde_json::Value> {
        let mut clean = args.clone();
        for (_, val) in clean.iter_mut() {
            if let Some(s) = val.as_str() {
                let mut sanitized = s.to_string();
                for c in SHELL_METACHARACTERS { sanitized = sanitized.replace(*c, ""); }
                if sanitized != s { *val = serde_json::Value::String(sanitized); }
            }
        }
        clean
    }

    fn check_chain(&self, agent_id: &str, tool: &str, now: i64, violations: &mut Vec<Violation>) {
        let mut chains = self.tool_chains.write();
        let chain = chains.entry(agent_id.into()).or_insert_with(VecDeque::new);
        chain.push_back((tool.into(), now));
        if chain.len() > 20 { chain.pop_front(); }
        let cutoff = now - 120;
        while chain.front().map_or(false, |(_, t)| *t < cutoff) { chain.pop_front(); }
        let names: Vec<&str> = chain.iter().map(|(n, _)| n.as_str()).collect();
        for (pattern, label) in DANGEROUS_CHAINS {
            if names.len() >= pattern.len() {
                for win in names.windows(pattern.len()) {
                    if win == *pattern {
                        violations.push(Violation { field: "chain".into(),
                            violation_type: ViolationType::DangerousChain,
                            message: format!("Dangerous tool chain: {}", label), severity: Severity::Critical });
                        self.add_alert(now, Severity::Critical, "Dangerous tool chain",
                            &format!("Agent {} matched '{}': {:?}", agent_id, label, pattern));
                        break;
                    }
                }
            }
        }
    }

    fn check_rate(&self, key: &str, max: u64, now: i64) -> bool {
        let mut counters = self.rate_counters.write();
        let dq = counters.entry(key.into()).or_insert_with(VecDeque::new);
        let cutoff = now - 60;
        while dq.front().map_or(false, |t| *t < cutoff) { dq.pop_front(); }
        if dq.len() as u64 >= max { return false; }
        dq.push_back(now); true
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(AiAlert { timestamp: ts, severity: sev, component: "tool_call_validator".into(),
            title: title.into(), details: details.into() });
    }

    pub fn total_validated(&self) -> u64 { self.total_validated.load(Ordering::Relaxed) }
    pub fn total_approved(&self) -> u64 { self.total_approved.load(Ordering::Relaxed) }
    pub fn total_rejected(&self) -> u64 { self.total_rejected.load(Ordering::Relaxed) }
    pub fn total_injections(&self) -> u64 { self.total_injections.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
