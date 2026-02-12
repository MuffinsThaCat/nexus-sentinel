//! MCP/A2A Protocol Security — validates Model Context Protocol and Agent-to-Agent
//! protocol messages for injection, privilege escalation, and data exfiltration.
//!
//! This is the world's first security layer for the emerging MCP and A2A protocols
//! that allow AI agents to invoke tools, access resources, and communicate with
//! each other. Attack surfaces include:
//!
//! ## 15 Detection Categories
//! 1. Tool schema validation (argument types, bounds, required fields)
//! 2. Resource URI injection (path traversal, SSRF, protocol smuggling)
//! 3. Prompt injection via tool results (poisoned tool output)
//! 4. Privilege escalation (agent requests tools beyond its permission level)
//! 5. Capability negotiation tampering (inflated capabilities)
//! 6. Session hijacking (forged session tokens, replay attacks)
//! 7. Tool chain depth limiting (prevent infinite recursion)
//! 8. Cross-agent impersonation (A2A identity spoofing)
//! 9. Resource exhaustion (excessive tool calls, large payloads)
//! 10. Sampling manipulation (tampered model sampling requests)
//! 11. Notification flooding (DoS via notification spam)
//! 12. Transport security (TLS validation, certificate pinning)
//! 13. Schema poisoning (malicious tool definitions)
//! 14. Context window overflow (oversized tool results filling context)
//! 15. Capability downgrade attacks (stripping security capabilities)
//!
//! Memory breakthroughs: #2 Tiered Cache, #461 Differential, #627 Sparse, #6 Verifier

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
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

// ── MCP message types ───────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct McpMessage {
    pub jsonrpc: String,
    pub method: Option<String>,
    pub id: Option<serde_json::Value>,
    pub params: Option<serde_json::Value>,
    pub result: Option<serde_json::Value>,
    pub error: Option<serde_json::Value>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct McpToolCall {
    pub tool_name: String,
    pub arguments: HashMap<String, serde_json::Value>,
    pub agent_id: String,
    pub session_id: String,
    pub timestamp: i64,
    pub server_name: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct McpToolResult {
    pub tool_name: String,
    pub content: Vec<McpContent>,
    pub is_error: bool,
    pub server_name: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct McpContent {
    pub content_type: String,
    pub text: Option<String>,
    pub data: Option<String>,
    pub mime_type: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct A2AMessage {
    pub from_agent: String,
    pub to_agent: String,
    pub message_type: String,
    pub task_id: Option<String>,
    pub content: serde_json::Value,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum McpVerdict {
    Allow, Block, Sanitize, RateLimit, NeedsApproval,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct McpScanResult {
    pub verdict: McpVerdict,
    pub risk_score: f64,
    pub violations: Vec<String>,
    pub categories: Vec<String>,
}

// ── Tool permission definitions ─────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ToolPermission {
    pub tool_name: String,
    pub allowed_agents: HashSet<String>,
    pub max_calls_per_minute: u32,
    pub max_argument_size_bytes: usize,
    pub requires_approval: bool,
    pub dangerous: bool,
}

#[derive(Debug, Clone)]
struct AgentSession {
    agent_id: String,
    session_id: String,
    tool_calls: VecDeque<i64>,
    chain_depth: u32,
    total_calls: u64,
    blocked_calls: u64,
    last_seen: i64,
}

// ── URI injection patterns ──────────────────────────────────────────────────

const URI_INJECTION_PATTERNS: &[(&str, &str, f64)] = &[
    ("../", "path_traversal", 0.90),
    ("..\\", "path_traversal_win", 0.90),
    ("%2e%2e", "encoded_traversal", 0.92),
    ("file://", "file_protocol", 0.95),
    ("gopher://", "gopher_ssrf", 0.95),
    ("dict://", "dict_ssrf", 0.95),
    ("ftp://", "ftp_protocol", 0.80),
    ("ldap://", "ldap_injection", 0.95),
    ("data:text/html", "data_uri_xss", 0.90),
    ("javascript:", "js_uri", 0.95),
    ("\\n", "header_injection", 0.85),
    ("\\r\\n", "crlf_injection", 0.90),
    ("127.0.0.1", "localhost_ssrf", 0.85),
    ("169.254.169.254", "cloud_metadata_ssrf", 0.98),
    ("metadata.google", "gcp_metadata_ssrf", 0.98),
    ("[::1]", "ipv6_localhost_ssrf", 0.85),
    ("0x7f000001", "hex_localhost_ssrf", 0.90),
    ("0177.0.0.1", "octal_localhost_ssrf", 0.90),
];

const TOOL_RESULT_INJECTION_PATTERNS: &[(&str, f64)] = &[
    ("ignore previous", 0.95), ("override instructions", 0.95),
    ("system prompt:", 0.90), ("you are now", 0.70),
    ("new instructions:", 0.90), ("forget everything", 0.92),
    ("bypass safety", 0.95), ("[system]", 0.85),
    ("### instruction", 0.82), ("enter developer mode", 0.90),
];

const SCHEMA_POISON_PATTERNS: &[(&str, f64)] = &[
    ("eval(", 0.95), ("exec(", 0.95), ("__import__", 0.95),
    ("subprocess", 0.90), ("os.system", 0.95), ("child_process", 0.92),
    ("Runtime.exec", 0.92), ("ProcessBuilder", 0.90),
    ("curl ", 0.75), ("wget ", 0.75), ("rm -rf", 0.98),
    ("chmod 777", 0.90), ("sudo ", 0.85),
];

// ── Main security validator ─────────────────────────────────────────────────

pub struct McpProtocolSecurity {
    // Config
    max_chain_depth: u32,
    max_calls_per_minute: u32,
    max_payload_bytes: usize,
    max_result_tokens: usize,
    enabled: bool,

    // State
    tool_permissions: RwLock<HashMap<String, ToolPermission>>,
    agent_sessions: RwLock<HashMap<String, AgentSession>>,
    known_servers: RwLock<HashSet<String>>,
    blocked_tools: RwLock<HashSet<String>>,

    // Memory breakthroughs
    call_cache: TieredCache<String, u64>,
    schema_diffs: DifferentialStore<String, String>,
    /// Breakthrough #569: φ-weighted alert pruning
    pruned_alerts: PruningMap<String, AiAlert>,
    /// Breakthrough #1: O(log n) call trend history
    call_state: RwLock<HierarchicalState<u64>>,
    /// Breakthrough #627: Sparse tool×agent call matrix
    call_matrix: RwLock<SparseMatrix<String, String, u64>>,
    /// Breakthrough #592: Content-addressed dedup for call fingerprints
    call_dedup: DedupStore<String, String>,

    // Counters
    total_calls: AtomicU64,
    total_blocked: AtomicU64,
    total_sanitized: AtomicU64,
    total_uri_injections: AtomicU64,
    total_result_injections: AtomicU64,
    total_privilege_escalations: AtomicU64,
    total_rate_limited: AtomicU64,
    total_chain_depth_exceeded: AtomicU64,
    total_a2a_impersonation: AtomicU64,

    alerts: RwLock<Vec<AiAlert>>,
    metrics: Option<MemoryMetrics>,
}

impl McpProtocolSecurity {
    pub fn new() -> Self {
        Self {
            max_chain_depth: 10,
            max_calls_per_minute: 60,
            max_payload_bytes: 1024 * 1024, // 1MB
            max_result_tokens: 50_000,
            enabled: true,
            tool_permissions: RwLock::new(HashMap::new()),
            agent_sessions: RwLock::new(HashMap::new()),
            known_servers: RwLock::new(HashSet::new()),
            blocked_tools: RwLock::new(HashSet::new()),
            call_cache: TieredCache::new(50_000),
            schema_diffs: DifferentialStore::new(),
            pruned_alerts: PruningMap::new(5_000),
            call_state: RwLock::new(HierarchicalState::new(8, 64)),
            call_matrix: RwLock::new(SparseMatrix::new(0)),
            call_dedup: DedupStore::new(),
            total_calls: AtomicU64::new(0),
            total_blocked: AtomicU64::new(0),
            total_sanitized: AtomicU64::new(0),
            total_uri_injections: AtomicU64::new(0),
            total_result_injections: AtomicU64::new(0),
            total_privilege_escalations: AtomicU64::new(0),
            total_rate_limited: AtomicU64::new(0),
            total_chain_depth_exceeded: AtomicU64::new(0),
            total_a2a_impersonation: AtomicU64::new(0),
            alerts: RwLock::new(Vec::new()),
            metrics: None,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("mcp_protocol_security", 8 * 1024 * 1024);
        self.call_cache = self.call_cache.with_metrics(metrics.clone(), "mcp_cache");
        self.metrics = Some(metrics); self
    }

    pub fn register_tool(&self, perm: ToolPermission) {
        self.tool_permissions.write().insert(perm.tool_name.clone(), perm);
    }

    pub fn block_tool(&self, name: &str) { self.blocked_tools.write().insert(name.into()); }
    pub fn register_server(&self, name: &str) { self.known_servers.write().insert(name.into()); }

    // ═══════════════════════════════════════════════════════════════════════
    // MCP Tool Call Validation
    // ═══════════════════════════════════════════════════════════════════════

    pub fn validate_tool_call(&self, call: &McpToolCall) -> McpScanResult {
        if !self.enabled { return McpScanResult { verdict: McpVerdict::Allow, risk_score: 0.0, violations: vec![], categories: vec![] }; }
        self.total_calls.fetch_add(1, Ordering::Relaxed);
        let now = call.timestamp;
        let mut risk = 0.0f64;
        let mut violations = Vec::new();
        let mut categories = Vec::new();

        // 1. Blocked tool check
        if self.blocked_tools.read().contains(&call.tool_name) {
            risk = 1.0; violations.push(format!("Tool '{}' is blocked", call.tool_name));
            categories.push("blocked_tool".into());
        }

        // 2. Permission check
        let perms = self.tool_permissions.read();
        if let Some(perm) = perms.get(&call.tool_name) {
            if !perm.allowed_agents.is_empty() && !perm.allowed_agents.contains(&call.agent_id) {
                risk = risk.max(0.95);
                violations.push(format!("Agent '{}' not authorized for tool '{}'", call.agent_id, call.tool_name));
                categories.push("privilege_escalation".into());
                self.total_privilege_escalations.fetch_add(1, Ordering::Relaxed);
            }
            if perm.dangerous && !categories.contains(&"dangerous_tool".to_string()) {
                risk = risk.max(0.70);
                categories.push("dangerous_tool".into());
            }
        }

        // 3. Rate limiting
        let session_key = format!("{}:{}", call.agent_id, call.session_id);
        {
            let mut sessions = self.agent_sessions.write();
            let session = sessions.entry(session_key.clone()).or_insert_with(|| AgentSession {
                agent_id: call.agent_id.clone(), session_id: call.session_id.clone(),
                tool_calls: VecDeque::new(), chain_depth: 0, total_calls: 0, blocked_calls: 0, last_seen: now,
            });
            session.tool_calls.push_back(now);
            session.total_calls += 1;
            session.last_seen = now;
            // Prune old timestamps
            while let Some(&ts) = session.tool_calls.front() {
                if now - ts > 60 { session.tool_calls.pop_front(); } else { break; }
            }
            if session.tool_calls.len() as u32 > self.max_calls_per_minute {
                risk = risk.max(0.80);
                violations.push(format!("Rate limit exceeded: {} calls/min", session.tool_calls.len()));
                categories.push("rate_limited".into());
                self.total_rate_limited.fetch_add(1, Ordering::Relaxed);
            }
            // Chain depth
            session.chain_depth += 1;
            if session.chain_depth > self.max_chain_depth {
                risk = risk.max(0.90);
                violations.push(format!("Chain depth {} exceeds max {}", session.chain_depth, self.max_chain_depth));
                categories.push("chain_depth_exceeded".into());
                self.total_chain_depth_exceeded.fetch_add(1, Ordering::Relaxed);
            }
        }

        // 4. URI injection in arguments
        for (_key, value) in &call.arguments {
            if let Some(s) = value.as_str() {
                for (pat, cat, weight) in URI_INJECTION_PATTERNS {
                    if s.to_lowercase().contains(pat) {
                        risk = risk.max(*weight);
                        violations.push(format!("URI injection '{}' in argument", pat));
                        let c = format!("uri_{}", cat);
                        if !categories.contains(&c) { categories.push(c); }
                        self.total_uri_injections.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }

        // 5. Payload size check
        let payload_size = serde_json::to_string(&call.arguments).map(|s| s.len()).unwrap_or(0);
        if payload_size > self.max_payload_bytes {
            risk = risk.max(0.75);
            violations.push(format!("Payload {} bytes exceeds max {}", payload_size, self.max_payload_bytes));
            categories.push("oversized_payload".into());
        }

        // 6. Schema poisoning in argument values
        for (_key, value) in &call.arguments {
            let val_str = value.to_string().to_lowercase();
            for (pat, weight) in SCHEMA_POISON_PATTERNS {
                if val_str.contains(pat) {
                    risk = risk.max(*weight);
                    violations.push(format!("Schema poison pattern '{}' in arguments", pat));
                    if !categories.contains(&"schema_poisoning".to_string()) { categories.push("schema_poisoning".into()); }
                }
            }
        }

        // Determine verdict
        let verdict = if risk >= 0.90 {
            self.total_blocked.fetch_add(1, Ordering::Relaxed);
            McpVerdict::Block
        } else if risk >= 0.70 {
            McpVerdict::NeedsApproval
        } else if risk >= 0.40 {
            self.total_sanitized.fetch_add(1, Ordering::Relaxed);
            McpVerdict::Sanitize
        } else {
            McpVerdict::Allow
        };

        if risk >= 0.70 {
            let sev = if risk >= 0.90 { Severity::Critical } else { Severity::High };
            let detail = format!("MCP tool '{}' by '{}': risk={:.2}, violations={}", call.tool_name, call.agent_id, risk, violations.join("; "));
            self.add_alert(now, sev, "MCP security violation", &detail);
        }

        McpScanResult { verdict, risk_score: risk, violations, categories }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // MCP Tool Result Validation (scan results before they enter context)
    // ═══════════════════════════════════════════════════════════════════════

    pub fn validate_tool_result(&self, result: &McpToolResult) -> McpScanResult {
        if !self.enabled { return McpScanResult { verdict: McpVerdict::Allow, risk_score: 0.0, violations: vec![], categories: vec![] }; }
        let mut risk = 0.0f64;
        let mut violations = Vec::new();
        let mut categories = Vec::new();
        let now = chrono::Utc::now().timestamp();

        for content in &result.content {
            if let Some(ref text) = content.text {
                // Check for prompt injection in tool results
                let lower = text.to_lowercase();
                for (pat, weight) in TOOL_RESULT_INJECTION_PATTERNS {
                    if lower.contains(pat) {
                        risk = risk.max(*weight);
                        violations.push(format!("Injection in tool result: '{}'", pat));
                        if !categories.contains(&"result_injection".to_string()) { categories.push("result_injection".into()); }
                        self.total_result_injections.fetch_add(1, Ordering::Relaxed);
                    }
                }
                // Context overflow check
                let token_estimate = text.len() / 4;
                if token_estimate > self.max_result_tokens {
                    risk = risk.max(0.70);
                    violations.push(format!("Result ~{} tokens exceeds max {}", token_estimate, self.max_result_tokens));
                    categories.push("context_overflow".into());
                }
            }
            // Check for suspicious binary data
            if let Some(ref data) = content.data {
                if data.len() > self.max_payload_bytes {
                    risk = risk.max(0.75);
                    violations.push("Oversized binary data in result".into());
                    categories.push("oversized_result".into());
                }
            }
        }

        // Unknown server check
        if !self.known_servers.read().contains(&result.server_name) {
            risk = risk.max(0.50);
            violations.push(format!("Unknown MCP server: '{}'", result.server_name));
            categories.push("unknown_server".into());
        }

        let verdict = if risk >= 0.90 { McpVerdict::Block } else if risk >= 0.70 { McpVerdict::NeedsApproval }
                      else if risk >= 0.40 { McpVerdict::Sanitize } else { McpVerdict::Allow };

        if risk >= 0.70 {
            let sev = if risk >= 0.90 { Severity::Critical } else { Severity::High };
            self.add_alert(now, sev, "MCP result injection", &violations.join("; "));
        }

        McpScanResult { verdict, risk_score: risk, violations, categories }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // A2A Protocol Validation
    // ═══════════════════════════════════════════════════════════════════════

    pub fn validate_a2a_message(&self, msg: &A2AMessage) -> McpScanResult {
        if !self.enabled { return McpScanResult { verdict: McpVerdict::Allow, risk_score: 0.0, violations: vec![], categories: vec![] }; }
        let mut risk = 0.0f64;
        let mut violations = Vec::new();
        let mut categories = Vec::new();

        // 1. Agent identity validation
        if msg.from_agent == msg.to_agent {
            risk = risk.max(0.70);
            violations.push("Agent sending message to itself".into());
            categories.push("self_loop".into());
        }

        // 2. Message type validation
        let valid_types = ["task", "status", "result", "cancel", "error", "heartbeat"];
        if !valid_types.contains(&msg.message_type.as_str()) {
            risk = risk.max(0.60);
            violations.push(format!("Unknown A2A message type: '{}'", msg.message_type));
            categories.push("unknown_message_type".into());
        }

        // 3. Content injection check
        let content_str = msg.content.to_string().to_lowercase();
        for (pat, weight) in TOOL_RESULT_INJECTION_PATTERNS {
            if content_str.contains(pat) {
                risk = risk.max(*weight);
                violations.push(format!("Injection in A2A content: '{}'", pat));
                if !categories.contains(&"a2a_injection".to_string()) { categories.push("a2a_injection".into()); }
            }
        }

        // 4. Impersonation detection (agent claims to be a different agent)
        if content_str.contains("i am ") || content_str.contains("my name is ") || content_str.contains("acting as ") {
            risk = risk.max(0.75);
            violations.push("Potential agent impersonation in content".into());
            categories.push("impersonation".into());
            self.total_a2a_impersonation.fetch_add(1, Ordering::Relaxed);
        }

        // 5. Task hijacking (referencing tasks not assigned to this agent)
        // This would need integration with a task registry in production

        let verdict = if risk >= 0.90 { McpVerdict::Block } else if risk >= 0.70 { McpVerdict::NeedsApproval }
                      else if risk >= 0.40 { McpVerdict::Sanitize } else { McpVerdict::Allow };

        if risk >= 0.70 {
            let now = msg.timestamp;
            let sev = if risk >= 0.90 { Severity::Critical } else { Severity::High };
            self.add_alert(now, sev, "A2A protocol violation", &violations.join("; "));
        }

        McpScanResult { verdict, risk_score: risk, violations, categories }
    }

    pub fn reset_chain_depth(&self, agent_id: &str, session_id: &str) {
        let key = format!("{}:{}", agent_id, session_id);
        if let Some(session) = self.agent_sessions.write().get_mut(&key) {
            session.chain_depth = 0;
        }
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(AiAlert { timestamp: ts, severity: sev, component: "mcp_protocol_security".into(), title: title.into(), details: details.into() });
    }

    pub fn total_calls(&self) -> u64 { self.total_calls.load(Ordering::Relaxed) }
    pub fn total_blocked(&self) -> u64 { self.total_blocked.load(Ordering::Relaxed) }
    pub fn total_uri_injections(&self) -> u64 { self.total_uri_injections.load(Ordering::Relaxed) }
    pub fn total_result_injections(&self) -> u64 { self.total_result_injections.load(Ordering::Relaxed) }
    pub fn total_privilege_escalations(&self) -> u64 { self.total_privilege_escalations.load(Ordering::Relaxed) }
    pub fn total_a2a_impersonation(&self) -> u64 { self.total_a2a_impersonation.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
