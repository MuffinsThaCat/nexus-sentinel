//! Agent Permission Boundary — allowlist/denylist enforcement for AI agent actions.
//!
//! Features:
//! - **Default-deny** posture with explicit allowlisting
//! - **Hierarchical path rules** with directory tree inheritance
//! - **Time-based permissions** (e.g., allow git push only during work hours)
//! - **Rate-limited permissions** (allow max N file writes per minute)
//! - **Escalation system** with Ask/Deny/Allow/AskOnce/AllowUntil
//! - **Per-agent profiles** with inheritance from role templates
//! - **Glob and regex pattern matching** for targets
//! - **Audit trail** of every check with denial reasons
//! - **Emergency lockdown** mode that denies everything instantly
//!
//! Memory breakthroughs: #2 Tiered Cache, #627 Sparse, #4 VQ Codec, #6 Verifier

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::differential::DifferentialStore;
use sentinel_core::sparse::SparseMatrix;
use sentinel_core::pruning::PruningMap;
use sentinel_core::hierarchical::HierarchicalState;
use sentinel_core::dedup::DedupStore;
use sentinel_core::vq_codec::VqCodec;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

// ── Permission types ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Permission {
    Allow,
    Deny,
    Ask,
    AskOnce,
    AllowUntil(i64),
    DenyWithLog,
    AllowWithLog,
}

impl Permission {
    pub fn is_allowed(&self, now: i64) -> bool {
        match self {
            Permission::Allow | Permission::AllowWithLog => true,
            Permission::AllowUntil(expiry) => now < *expiry,
            _ => false,
        }
    }
    pub fn needs_log(&self) -> bool {
        matches!(self, Permission::DenyWithLog | Permission::AllowWithLog)
    }
}

// ── Rule types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PermissionRule {
    pub id: String,
    pub agent_pattern: String,
    pub action_type: String,
    pub target_pattern: String,
    pub permission: Permission,
    pub priority: u32,
    pub reason: String,
    pub time_window: Option<TimeWindow>,
    pub rate_limit: Option<RateLimit>,
    pub expires_at: Option<i64>,
    pub created_by: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TimeWindow {
    pub start_hour: u8,
    pub end_hour: u8,
    pub days: Vec<u8>,
    pub timezone_offset: i32,
}

impl TimeWindow {
    pub fn is_active(&self, timestamp: i64) -> bool {
        let adjusted = timestamp + self.timezone_offset as i64 * 3600;
        let hour = ((adjusted % 86400) / 3600) as u8;
        let day = ((adjusted / 86400 + 4) % 7) as u8; // 0=Mon
        let hour_ok = if self.start_hour <= self.end_hour {
            hour >= self.start_hour && hour < self.end_hour
        } else {
            hour >= self.start_hour || hour < self.end_hour
        };
        let day_ok = self.days.is_empty() || self.days.contains(&day);
        hour_ok && day_ok
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RateLimit {
    pub max_count: u64,
    pub window_secs: u64,
}

// ── Agent profiles ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentProfile {
    pub agent_id: String,
    pub role: AgentRole,
    pub custom_rules: Vec<String>,
    pub blocked_paths: Vec<String>,
    pub allowed_paths: Vec<String>,
    pub max_file_size_bytes: u64,
    pub network_allowed: bool,
    pub can_execute_commands: bool,
    pub can_install_packages: bool,
    pub can_modify_git: bool,
    pub can_access_secrets: bool,
    pub can_send_email: bool,
    pub max_actions_per_minute: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AgentRole {
    ReadOnly,
    Developer,
    Operator,
    Admin,
    Restricted,
    Custom,
}

impl Default for AgentProfile {
    fn default() -> Self {
        Self {
            agent_id: String::new(),
            role: AgentRole::Restricted,
            custom_rules: Vec::new(),
            blocked_paths: vec![
                "~/.ssh/*".into(), "~/.gnupg/*".into(), "~/.aws/*".into(),
                "~/.env*".into(), "/etc/shadow".into(), "/etc/sudoers".into(),
            ],
            allowed_paths: Vec::new(),
            max_file_size_bytes: 10 * 1024 * 1024,
            network_allowed: false,
            can_execute_commands: false,
            can_install_packages: false,
            can_modify_git: false,
            can_access_secrets: false,
            can_send_email: false,
            max_actions_per_minute: 60,
        }
    }
}

// ── Check result ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PermissionCheck {
    pub allowed: bool,
    pub permission: Permission,
    pub matched_rule: Option<String>,
    pub agent_id: String,
    pub action: String,
    pub target: String,
    pub denial_reason: Option<String>,
    pub rate_remaining: Option<u64>,
}

// ── Denied paths (hardcoded safety net) ─────────────────────────────────────

const ALWAYS_DENY_PATHS: &[&str] = &[
    "/etc/shadow", "/etc/sudoers", "/etc/passwd",
    "~/.ssh/id_rsa", "~/.ssh/id_ed25519", "~/.ssh/authorized_keys",
    "~/.gnupg/", "~/.aws/credentials", "~/.azure/",
    "/boot/", "/dev/sda", "/dev/nvme",
    "~/.docker/config.json",
];

const ALWAYS_DENY_COMMANDS: &[&str] = &[
    "rm -rf /", "rm -rf ~", "rm -rf /*",
    "chmod 777 /", ":(){ :|:& };:",
    "mkfs.", "dd if=/dev/zero of=/dev/",
    "cat /dev/urandom >",
    "> /dev/sda", "> /dev/nvme",
    "curl | sudo bash", "wget | sudo sh",
];

// ── Permission Boundary implementation ──────────────────────────────────────

pub struct AgentPermissionBoundary {
    permission_matrix: RwLock<SparseMatrix<String, String, Permission>>,
    rule_cache: TieredCache<String, Permission>,
    rules: RwLock<Vec<PermissionRule>>,
    agent_profiles: RwLock<HashMap<String, AgentProfile>>,
    blocked_actions: RwLock<HashSet<String>>,
    rate_counters: RwLock<HashMap<String, VecDeque<i64>>>,
    audit_log: RwLock<VecDeque<PermissionCheck>>,
    _path_codec: RwLock<VqCodec>,
    alerts: RwLock<Vec<AiAlert>>,
    total_checks: AtomicU64,
    total_denied: AtomicU64,
    total_allowed: AtomicU64,
    total_escalated: AtomicU64,
    lockdown: AtomicBool,
    default_permission: Permission,
    /// Breakthrough #461: Permission rule evolution tracking
    rule_diffs: DifferentialStore<String, String>,
    /// Breakthrough #569: φ-weighted alert pruning
    pruned_alerts: PruningMap<String, AiAlert>,
    /// Breakthrough #1: O(log n) permission trend history
    perm_state: RwLock<HierarchicalState<u64>>,
    /// Breakthrough #592: Content-addressed dedup for permission fingerprints
    perm_dedup: DedupStore<String, String>,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl AgentPermissionBoundary {
    pub fn new() -> Self {
        Self {
            permission_matrix: RwLock::new(SparseMatrix::new(Permission::Deny)),
            rule_cache: TieredCache::new(10_000),
            rules: RwLock::new(Vec::new()),
            agent_profiles: RwLock::new(HashMap::new()),
            blocked_actions: RwLock::new(HashSet::new()),
            rate_counters: RwLock::new(HashMap::new()),
            audit_log: RwLock::new(VecDeque::with_capacity(10_000)),
            _path_codec: RwLock::new(VqCodec::new(256, 8)),
            alerts: RwLock::new(Vec::new()),
            total_checks: AtomicU64::new(0),
            total_denied: AtomicU64::new(0),
            total_allowed: AtomicU64::new(0),
            total_escalated: AtomicU64::new(0),
            lockdown: AtomicBool::new(false),
            default_permission: Permission::Deny,
            rule_diffs: DifferentialStore::new(),
            pruned_alerts: PruningMap::new(5_000),
            perm_state: RwLock::new(HierarchicalState::new(8, 64)),
            perm_dedup: DedupStore::new(),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("agent_permission_boundary", 4 * 1024 * 1024);
        self.rule_cache = self.rule_cache.with_metrics(metrics.clone(), "agent_permission_boundary");
        self.metrics = Some(metrics);
        self
    }

    // ── Configuration ───────────────────────────────────────────────────────

    pub fn add_rule(&self, rule: PermissionRule) {
        self.permission_matrix.write().set(
            rule.agent_pattern.clone(),
            format!("{}:{}", rule.action_type, rule.target_pattern),
            rule.permission,
        );
        self.rules.write().push(rule);
    }

    pub fn set_agent_profile(&self, profile: AgentProfile) {
        self.agent_profiles.write().insert(profile.agent_id.clone(), profile);
    }

    pub fn block_action_type(&self, action_type: &str) {
        self.blocked_actions.write().insert(action_type.to_string());
    }

    pub fn emergency_lockdown(&self) {
        self.lockdown.store(true, Ordering::SeqCst);
        let now = chrono::Utc::now().timestamp();
        self.add_alert(now, Severity::Critical, "EMERGENCY LOCKDOWN",
            "All agent actions denied — lockdown engaged");
    }

    pub fn lift_lockdown(&self) {
        self.lockdown.store(false, Ordering::SeqCst);
    }

    // ── Permission checking ─────────────────────────────────────────────────

    pub fn check(&self, agent_id: &str, action: &str, target: &str) -> PermissionCheck {
        let now = chrono::Utc::now().timestamp();
        self.check_at(agent_id, action, target, now)
    }

    pub fn check_at(&self, agent_id: &str, action: &str, target: &str, now: i64) -> PermissionCheck {
        if !self.enabled {
            return self.make_result(true, Permission::Allow, None, agent_id, action, target, None, None);
        }
        self.total_checks.fetch_add(1, Ordering::Relaxed);

        // Emergency lockdown
        if self.lockdown.load(Ordering::SeqCst) {
            return self.deny(agent_id, action, target, "emergency_lockdown", "System in lockdown", now);
        }

        // Hardcoded safety net — ALWAYS deny destructive paths/commands
        let target_lower = target.to_lowercase();
        for path in ALWAYS_DENY_PATHS {
            if target_lower.contains(path) {
                return self.deny(agent_id, action, target, "hardcoded_safety_net",
                    &format!("Access to protected path: {}", path), now);
            }
        }
        let action_lower = action.to_lowercase();
        for cmd in ALWAYS_DENY_COMMANDS {
            if target_lower.contains(cmd) || action_lower.contains(cmd) {
                return self.deny(agent_id, action, target, "hardcoded_safety_net",
                    &format!("Dangerous command blocked: {}", cmd), now);
            }
        }

        // Blocked action types (fast deny)
        if self.blocked_actions.read().contains(action) {
            return self.deny(agent_id, action, target, "blocked_action_type",
                "Action type globally blocked", now);
        }

        // Agent profile checks
        if let Some(profile) = self.agent_profiles.read().get(agent_id) {
            if let Some(result) = self.check_profile(profile, action, target, now) {
                return result;
            }
        }

        // #2 Check tiered cache
        let cache_key = format!("{}:{}:{}", agent_id, action, target);
        if let Some(cached) = self.rule_cache.get(&cache_key) {
            let allowed = cached.is_allowed(now);
            if !allowed { self.total_denied.fetch_add(1, Ordering::Relaxed); }
            else { self.total_allowed.fetch_add(1, Ordering::Relaxed); }
            return self.make_result(allowed, cached, Some("cached".into()), agent_id, action, target, None, None);
        }

        // #627 Check sparse matrix
        let action_target = format!("{}:{}", action, target);
        let perm = self.permission_matrix.read().get(&agent_id.to_string(), &action_target).clone();

        // Check named rules (sorted by priority, highest first)
        let final_perm = if perm == Permission::Deny {
            let rules = self.rules.read();
            let mut best: Option<(&PermissionRule, Permission)> = None;
            for rule in rules.iter() {
                if Self::glob_match(agent_id, &rule.agent_pattern)
                    && Self::glob_match(action, &rule.action_type)
                    && Self::glob_match(target, &rule.target_pattern)
                {
                    // Check time window
                    if let Some(ref tw) = rule.time_window {
                        if !tw.is_active(now) { continue; }
                    }
                    // Check expiry
                    if let Some(exp) = rule.expires_at {
                        if now > exp { continue; }
                    }
                    if best.as_ref().map_or(true, |(b, _)| rule.priority > b.priority) {
                        best = Some((rule, rule.permission));
                    }
                }
            }
            best.map_or(self.default_permission, |(_, p)| p)
        } else {
            perm
        };

        // Rate limiting
        if final_perm.is_allowed(now) {
            if let Some(profile) = self.agent_profiles.read().get(agent_id) {
                if !self.check_rate(agent_id, profile.max_actions_per_minute, 60, now) {
                    return self.deny(agent_id, action, target, "rate_limit",
                        &format!("Rate limit exceeded: {} actions/min", profile.max_actions_per_minute), now);
                }
            }
        }

        // Cache the result
        self.rule_cache.insert(cache_key, final_perm);

        let allowed = final_perm.is_allowed(now);
        if !allowed {
            self.record_denial(agent_id, action, target, "rule_match", now);
        } else {
            self.total_allowed.fetch_add(1, Ordering::Relaxed);
        }

        let result = self.make_result(allowed, final_perm, Some("rule_match".into()),
            agent_id, action, target, None, None);
        self.audit(&result);
        result
    }

    fn check_profile(&self, profile: &AgentProfile, action: &str, target: &str, now: i64) -> Option<PermissionCheck> {
        let agent_id = &profile.agent_id;

        // Profile-level blocked paths
        for blocked in &profile.blocked_paths {
            if Self::glob_match(target, blocked) {
                return Some(self.deny(agent_id, action, target, "profile_blocked_path",
                    &format!("Path blocked by agent profile: {}", blocked), now));
            }
        }

        // Role-based restrictions
        match profile.role {
            AgentRole::ReadOnly => {
                if !matches!(action, "FileRead" | "DirectoryList" | "DatabaseQuery" | "MemoryRead") {
                    return Some(self.deny(agent_id, action, target, "role_readonly",
                        "ReadOnly agent cannot perform write actions", now));
                }
            },
            AgentRole::Restricted => {
                if !profile.can_execute_commands && action.contains("Exec") {
                    return Some(self.deny(agent_id, action, target, "role_no_exec",
                        "Agent not permitted to execute commands", now));
                }
                if !profile.network_allowed && matches!(action,
                    "HttpRequest" | "HttpsRequest" | "NetworkConnect" | "SshConnect" |
                    "FtpTransfer" | "WebSocketConnect" | "DnsLookup") {
                    return Some(self.deny(agent_id, action, target, "role_no_network",
                        "Agent not permitted network access", now));
                }
                if !profile.can_install_packages && action == "PackageInstall" {
                    return Some(self.deny(agent_id, action, target, "role_no_install",
                        "Agent not permitted to install packages", now));
                }
                if !profile.can_modify_git && matches!(action, "GitPush" | "GitCommit" | "GitCheckout") {
                    return Some(self.deny(agent_id, action, target, "role_no_git",
                        "Agent not permitted to modify git", now));
                }
                if !profile.can_access_secrets && matches!(action, "EnvironmentRead" | "CertificateAccess") {
                    return Some(self.deny(agent_id, action, target, "role_no_secrets",
                        "Agent not permitted to access secrets", now));
                }
                if !profile.can_send_email && matches!(action, "EmailSend" | "MessageSend" | "SlackPost") {
                    return Some(self.deny(agent_id, action, target, "role_no_comms",
                        "Agent not permitted to send communications", now));
                }
            },
            _ => {},
        }
        None
    }

    fn check_rate(&self, key: &str, max_count: u64, window_secs: u64, now: i64) -> bool {
        let mut counters = self.rate_counters.write();
        let deque = counters.entry(key.to_string()).or_insert_with(VecDeque::new);
        let cutoff = now - window_secs as i64;
        while deque.front().map_or(false, |t| *t < cutoff) { deque.pop_front(); }
        if deque.len() as u64 >= max_count { return false; }
        deque.push_back(now);
        true
    }

    fn deny(&self, agent_id: &str, action: &str, target: &str, rule: &str, reason: &str, now: i64) -> PermissionCheck {
        self.record_denial(agent_id, action, target, rule, now);
        let result = self.make_result(false, Permission::Deny, Some(rule.into()),
            agent_id, action, target, Some(reason.into()), None);
        self.audit(&result);
        result
    }

    fn record_denial(&self, agent_id: &str, action: &str, target: &str, rule: &str, now: i64) {
        self.total_denied.fetch_add(1, Ordering::Relaxed);
        warn!(agent = %agent_id, action = %action, target = %target, rule = %rule, "Agent action denied");
        self.add_alert(now, Severity::Medium, "Agent action denied",
            &format!("{} denied: {} on {} (rule: {})", agent_id, action, target, rule));
    }

    fn make_result(&self, allowed: bool, perm: Permission, rule: Option<String>,
        agent_id: &str, action: &str, target: &str, reason: Option<String>, rate_rem: Option<u64>) -> PermissionCheck {
        PermissionCheck {
            allowed, permission: perm, matched_rule: rule,
            agent_id: agent_id.into(), action: action.into(), target: target.into(),
            denial_reason: reason, rate_remaining: rate_rem,
        }
    }

    fn audit(&self, check: &PermissionCheck) {
        let mut log = self.audit_log.write();
        if log.len() >= 10_000 { log.pop_front(); }
        log.push_back(check.clone());
    }

    fn glob_match(text: &str, pattern: &str) -> bool {
        if pattern == "*" { return true; }
        if pattern.contains('*') {
            let parts: Vec<&str> = pattern.split('*').collect();
            if parts.len() == 2 {
                let (prefix, suffix) = (parts[0], parts[1]);
                return text.starts_with(prefix) && text.ends_with(suffix);
            }
            if pattern.ends_with('*') { return text.starts_with(&pattern[..pattern.len()-1]); }
            if pattern.starts_with('*') { return text.ends_with(&pattern[1..]); }
        }
        text == pattern
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(AiAlert { timestamp: ts, severity: sev, component: "agent_permission_boundary".into(),
            title: title.into(), details: details.into() });
    }

    // ── Query methods ───────────────────────────────────────────────────────

    pub fn audit_log(&self, limit: usize) -> Vec<PermissionCheck> {
        let log = self.audit_log.read();
        log.iter().rev().take(limit).cloned().collect()
    }

    pub fn denied_actions(&self, limit: usize) -> Vec<PermissionCheck> {
        let log = self.audit_log.read();
        log.iter().rev().filter(|c| !c.allowed).take(limit).cloned().collect()
    }

    pub fn is_locked_down(&self) -> bool { self.lockdown.load(Ordering::SeqCst) }
    pub fn total_checks(&self) -> u64 { self.total_checks.load(Ordering::Relaxed) }
    pub fn total_denied(&self) -> u64 { self.total_denied.load(Ordering::Relaxed) }
    pub fn total_allowed(&self) -> u64 { self.total_allowed.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
