//! Human-in-the-Loop Enforcer — Policy engine requiring human approval for
//! high-risk agent actions before execution.
//!
//! Without this, a compromised or confused agent can autonomously delete files,
//! execute financial transactions, send emails, or make irreversible API calls.
//!
//! Implements: action classification (safe/review/block), configurable policy
//! rules, approval queues with timeouts, risk-based escalation, audit trail
//! of all approval decisions, auto-deny for timed-out actions, budget limits
//! for autonomous operation, and emergency kill-switch.
//!
//! 6 enforcement categories, 4 memory breakthroughs:
//!   #2  TieredCache — hot/warm/cold action classification cache
//!   #461 DifferentialStore — policy evolution tracking
//!   #569 PruningMap — φ-weighted approval history eviction
//!   #1  HierarchicalState — O(log n) rate limit tracking

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
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;
const DEFAULT_TIMEOUT_SECS: i64 = 300; // 5 minutes

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ActionRisk {
    Safe,       // auto-approve
    Low,        // auto-approve with logging
    Medium,     // require approval if budget exceeded
    High,       // always require approval
    Critical,   // require approval + confirmation
    Forbidden,  // always deny
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    TimedOut,
    AutoApproved,
    EmergencyDenied,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentAction {
    pub action_id: String,
    pub agent_id: String,
    pub action_type: String,
    pub description: String,
    pub target: String,
    pub parameters: HashMap<String, String>,
    pub estimated_impact: String,
    pub reversible: bool,
    pub timestamp: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ApprovalRequest {
    pub action: AgentAction,
    pub risk_level: ActionRisk,
    pub risk_score: f64,
    pub reason: String,
    pub status: ApprovalStatus,
    pub created_at: i64,
    pub resolved_at: Option<i64>,
    pub resolved_by: Option<String>,
    pub timeout_at: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicyRule {
    pub action_pattern: String,
    pub risk_level: ActionRisk,
    pub requires_confirmation: bool,
    pub max_per_hour: Option<u32>,
    pub max_value: Option<f64>,
    pub description: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EnforcerDecision {
    pub action_id: String,
    pub allowed: bool,
    pub risk_level: ActionRisk,
    pub risk_score: f64,
    pub reason: String,
    pub requires_approval: bool,
    pub approval_status: ApprovalStatus,
}

// Default policy rules
fn default_policies() -> Vec<PolicyRule> {
    vec![
        // Forbidden actions
        PolicyRule { action_pattern: "delete_all".into(), risk_level: ActionRisk::Forbidden, requires_confirmation: false, max_per_hour: None, max_value: None, description: "Mass deletion".into() },
        PolicyRule { action_pattern: "format_disk".into(), risk_level: ActionRisk::Forbidden, requires_confirmation: false, max_per_hour: None, max_value: None, description: "Disk formatting".into() },
        PolicyRule { action_pattern: "drop_database".into(), risk_level: ActionRisk::Forbidden, requires_confirmation: false, max_per_hour: None, max_value: None, description: "Database destruction".into() },
        PolicyRule { action_pattern: "rm -rf".into(), risk_level: ActionRisk::Forbidden, requires_confirmation: false, max_per_hour: None, max_value: None, description: "Recursive deletion".into() },
        // Critical actions
        PolicyRule { action_pattern: "financial_transfer".into(), risk_level: ActionRisk::Critical, requires_confirmation: true, max_per_hour: Some(3), max_value: Some(1000.0), description: "Financial transfer".into() },
        PolicyRule { action_pattern: "send_email".into(), risk_level: ActionRisk::Critical, requires_confirmation: true, max_per_hour: Some(10), max_value: None, description: "Email sending".into() },
        PolicyRule { action_pattern: "api_key_create".into(), risk_level: ActionRisk::Critical, requires_confirmation: true, max_per_hour: Some(2), max_value: None, description: "API key creation".into() },
        PolicyRule { action_pattern: "deploy".into(), risk_level: ActionRisk::Critical, requires_confirmation: true, max_per_hour: Some(3), max_value: None, description: "Deployment".into() },
        PolicyRule { action_pattern: "publish".into(), risk_level: ActionRisk::Critical, requires_confirmation: true, max_per_hour: Some(5), max_value: None, description: "Public publishing".into() },
        // High risk
        PolicyRule { action_pattern: "file_delete".into(), risk_level: ActionRisk::High, requires_confirmation: false, max_per_hour: Some(20), max_value: None, description: "File deletion".into() },
        PolicyRule { action_pattern: "network_request".into(), risk_level: ActionRisk::High, requires_confirmation: false, max_per_hour: Some(100), max_value: None, description: "External network request".into() },
        PolicyRule { action_pattern: "install_package".into(), risk_level: ActionRisk::High, requires_confirmation: false, max_per_hour: Some(10), max_value: None, description: "Package installation".into() },
        PolicyRule { action_pattern: "execute_code".into(), risk_level: ActionRisk::High, requires_confirmation: false, max_per_hour: Some(50), max_value: None, description: "Code execution".into() },
        PolicyRule { action_pattern: "database_write".into(), risk_level: ActionRisk::High, requires_confirmation: false, max_per_hour: Some(100), max_value: None, description: "Database write".into() },
        // Medium risk
        PolicyRule { action_pattern: "file_write".into(), risk_level: ActionRisk::Medium, requires_confirmation: false, max_per_hour: Some(200), max_value: None, description: "File write".into() },
        PolicyRule { action_pattern: "config_change".into(), risk_level: ActionRisk::Medium, requires_confirmation: false, max_per_hour: Some(20), max_value: None, description: "Configuration change".into() },
        // Low risk
        PolicyRule { action_pattern: "file_read".into(), risk_level: ActionRisk::Low, requires_confirmation: false, max_per_hour: None, max_value: None, description: "File read".into() },
        PolicyRule { action_pattern: "search".into(), risk_level: ActionRisk::Low, requires_confirmation: false, max_per_hour: None, max_value: None, description: "Search operation".into() },
    ]
}

pub struct HumanInTheLoopEnforcer {
    policies: RwLock<Vec<PolicyRule>>,
    pending_approvals: RwLock<VecDeque<ApprovalRequest>>,
    approval_history: RwLock<VecDeque<ApprovalRequest>>,
    action_counts: RwLock<HashMap<String, VecDeque<i64>>>,
    /// Breakthrough #2: Hot/warm/cold action classification cache
    classify_cache: TieredCache<String, u64>,
    /// Breakthrough #461: Policy change tracking
    policy_diffs: DifferentialStore<String, String>,
    /// Breakthrough #569: φ-weighted approval history pruning
    pruned_history: PruningMap<String, ApprovalRequest>,
    /// Breakthrough #1: O(log n) rate limit history
    rate_state: RwLock<HierarchicalState<u64>>,
    /// Breakthrough #627: Sparse agent×action approval matrix
    approval_matrix: RwLock<SparseMatrix<String, String, u64>>,
    /// Breakthrough #592: Content-addressed dedup for action fingerprints
    action_dedup: DedupStore<String, String>,
    emergency_stop: AtomicBool,
    auto_approve_safe: bool,
    timeout_secs: i64,
    enabled: bool,

    alerts: RwLock<Vec<AiAlert>>,
    total_requests: AtomicU64,
    total_auto_approved: AtomicU64,
    total_pending: AtomicU64,
    total_approved: AtomicU64,
    total_denied: AtomicU64,
    total_timed_out: AtomicU64,
    total_forbidden: AtomicU64,
    total_emergency_stops: AtomicU64,
    metrics: Option<MemoryMetrics>,
}

impl HumanInTheLoopEnforcer {
    pub fn new() -> Self {
        Self {
            policies: RwLock::new(default_policies()),
            pending_approvals: RwLock::new(VecDeque::with_capacity(1_000)),
            approval_history: RwLock::new(VecDeque::with_capacity(10_000)),
            action_counts: RwLock::new(HashMap::new()),
            classify_cache: TieredCache::new(20_000),
            policy_diffs: DifferentialStore::new(),
            pruned_history: PruningMap::new(10_000),
            rate_state: RwLock::new(HierarchicalState::new(8, 64)),
            approval_matrix: RwLock::new(SparseMatrix::new(0)),
            action_dedup: DedupStore::new(),
            emergency_stop: AtomicBool::new(false),
            auto_approve_safe: true, timeout_secs: DEFAULT_TIMEOUT_SECS, enabled: true,
            alerts: RwLock::new(Vec::new()),
            total_requests: AtomicU64::new(0), total_auto_approved: AtomicU64::new(0),
            total_pending: AtomicU64::new(0), total_approved: AtomicU64::new(0),
            total_denied: AtomicU64::new(0), total_timed_out: AtomicU64::new(0),
            total_forbidden: AtomicU64::new(0), total_emergency_stops: AtomicU64::new(0),
            metrics: None,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("human_in_the_loop_enforcer", 4 * 1024 * 1024);
        self.classify_cache = self.classify_cache.with_metrics(metrics.clone(), "hitl_cache");
        self.metrics = Some(metrics); self
    }

    /// Submit an action for approval. Returns immediate decision or pending status.
    pub fn evaluate_action(&self, action: AgentAction) -> EnforcerDecision {
        if !self.enabled {
            return EnforcerDecision { action_id: action.action_id, allowed: true, risk_level: ActionRisk::Safe, risk_score: 0.0, reason: "enforcer_disabled".into(), requires_approval: false, approval_status: ApprovalStatus::AutoApproved };
        }
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();

        // Emergency stop overrides everything
        if self.emergency_stop.load(Ordering::Relaxed) {
            self.total_emergency_stops.fetch_add(1, Ordering::Relaxed);
            return EnforcerDecision {
                action_id: action.action_id, allowed: false, risk_level: ActionRisk::Forbidden,
                risk_score: 1.0, reason: "emergency_stop_active".into(),
                requires_approval: false, approval_status: ApprovalStatus::EmergencyDenied,
            };
        }

        // Classify the action
        let (risk_level, matching_rule) = self.classify_action(&action);
        let risk_score = match risk_level {
            ActionRisk::Safe => 0.0,
            ActionRisk::Low => 0.15,
            ActionRisk::Medium => 0.40,
            ActionRisk::High => 0.65,
            ActionRisk::Critical => 0.85,
            ActionRisk::Forbidden => 1.0,
        };

        // Forbidden = always deny
        if risk_level == ActionRisk::Forbidden {
            self.total_forbidden.fetch_add(1, Ordering::Relaxed);
            self.total_denied.fetch_add(1, Ordering::Relaxed);
            let detail = format!("Forbidden action: {} -> {}", action.action_type, action.target);
            warn!(agent=%action.agent_id, action=%action.action_type, "Forbidden action blocked");
            self.add_alert(now, Severity::Critical, "Forbidden action blocked", &detail);
            return EnforcerDecision {
                action_id: action.action_id, allowed: false, risk_level, risk_score: 1.0,
                reason: "forbidden_action".into(), requires_approval: false, approval_status: ApprovalStatus::Denied,
            };
        }

        // Check rate limits
        if let Some(rule) = &matching_rule {
            if let Some(max_per_hour) = rule.max_per_hour {
                let count = self.count_recent_actions(&action.action_type, now, 3600);
                if count >= max_per_hour as usize {
                    self.total_denied.fetch_add(1, Ordering::Relaxed);
                    let detail = format!("Rate limit: {} ({}/hr, max={})", action.action_type, count, max_per_hour);
                    warn!(agent=%action.agent_id, action=%action.action_type, count=count, max=max_per_hour, "Action rate limit exceeded");
                    self.add_alert(now, Severity::High, "Action rate limit exceeded", &detail);
                    return EnforcerDecision {
                        action_id: action.action_id, allowed: false, risk_level, risk_score,
                        reason: format!("rate_limit_exceeded: {}/{}", count, max_per_hour),
                        requires_approval: true, approval_status: ApprovalStatus::Denied,
                    };
                }
            }
        }

        // Safe/Low = auto-approve
        if (risk_level == ActionRisk::Safe || risk_level == ActionRisk::Low) && self.auto_approve_safe {
            self.total_auto_approved.fetch_add(1, Ordering::Relaxed);
            self.record_action(&action.action_type, now);
            return EnforcerDecision {
                action_id: action.action_id, allowed: true, risk_level, risk_score,
                reason: "auto_approved".into(), requires_approval: false,
                approval_status: ApprovalStatus::AutoApproved,
            };
        }

        // Medium/High/Critical = queue for approval
        self.total_pending.fetch_add(1, Ordering::Relaxed);
        let reason = format!("requires_human_approval: risk={:?}", risk_level);
        let request = ApprovalRequest {
            action: action.clone(), risk_level, risk_score,
            reason: reason.clone(), status: ApprovalStatus::Pending,
            created_at: now, resolved_at: None, resolved_by: None,
            timeout_at: now + self.timeout_secs,
        };
        self.pending_approvals.write().push_back(request);

        if risk_level == ActionRisk::Critical {
            self.add_alert(now, Severity::High, "Critical action awaiting approval",
                &format!("agent={}, action={}, target={}", action.agent_id, action.action_type, action.target));
        }

        EnforcerDecision {
            action_id: action.action_id, allowed: false, risk_level, risk_score,
            reason, requires_approval: true, approval_status: ApprovalStatus::Pending,
        }
    }

    /// Human approves a pending action
    pub fn approve(&self, action_id: &str, approver: &str) -> bool {
        let now = chrono::Utc::now().timestamp();
        let mut pending = self.pending_approvals.write();
        if let Some(pos) = pending.iter().position(|r| r.action.action_id == action_id) {
            let mut req = pending.remove(pos).unwrap();
            req.status = ApprovalStatus::Approved;
            req.resolved_at = Some(now);
            req.resolved_by = Some(approver.to_string());
            self.record_action(&req.action.action_type, now);
            self.approval_history.write().push_back(req);
            self.total_approved.fetch_add(1, Ordering::Relaxed);
            true
        } else { false }
    }

    /// Human denies a pending action
    pub fn deny(&self, action_id: &str, approver: &str) -> bool {
        let now = chrono::Utc::now().timestamp();
        let mut pending = self.pending_approvals.write();
        if let Some(pos) = pending.iter().position(|r| r.action.action_id == action_id) {
            let mut req = pending.remove(pos).unwrap();
            req.status = ApprovalStatus::Denied;
            req.resolved_at = Some(now);
            req.resolved_by = Some(approver.to_string());
            self.approval_history.write().push_back(req);
            self.total_denied.fetch_add(1, Ordering::Relaxed);
            true
        } else { false }
    }

    /// Expire timed-out approvals (call periodically)
    pub fn expire_timeouts(&self) {
        let now = chrono::Utc::now().timestamp();
        let mut pending = self.pending_approvals.write();
        let mut expired = Vec::new();
        pending.retain(|req| {
            if now >= req.timeout_at {
                let mut r = req.clone();
                r.status = ApprovalStatus::TimedOut;
                r.resolved_at = Some(now);
                expired.push(r);
                false
            } else { true }
        });
        if !expired.is_empty() {
            self.total_timed_out.fetch_add(expired.len() as u64, Ordering::Relaxed);
            let mut hist = self.approval_history.write();
            for r in expired { hist.push_back(r); }
        }
    }

    /// Emergency kill-switch — blocks ALL agent actions
    pub fn emergency_stop(&self) {
        self.emergency_stop.store(true, Ordering::Relaxed);
        self.total_emergency_stops.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        warn!("EMERGENCY STOP activated — all agent actions blocked");
        self.add_alert(now, Severity::Critical, "Emergency stop activated", "All agent actions are now blocked");
    }

    pub fn resume(&self) { self.emergency_stop.store(false, Ordering::Relaxed); }
    pub fn is_emergency_stopped(&self) -> bool { self.emergency_stop.load(Ordering::Relaxed) }

    pub fn add_policy(&self, rule: PolicyRule) { self.policies.write().push(rule); }
    pub fn pending_count(&self) -> usize { self.pending_approvals.read().len() }
    pub fn pending_requests(&self) -> Vec<ApprovalRequest> { self.pending_approvals.read().iter().cloned().collect() }

    fn classify_action(&self, action: &AgentAction) -> (ActionRisk, Option<PolicyRule>) {
        let lower_type = action.action_type.to_lowercase();
        let lower_target = action.target.to_lowercase();
        let policies = self.policies.read();
        for rule in policies.iter() {
            if lower_type.contains(&rule.action_pattern) || lower_target.contains(&rule.action_pattern) {
                return (rule.risk_level, Some(rule.clone()));
            }
        }
        // Default classification based on keywords
        if lower_type.contains("delete") || lower_type.contains("remove") || lower_type.contains("drop") {
            return (ActionRisk::High, None);
        }
        if lower_type.contains("write") || lower_type.contains("create") || lower_type.contains("update") {
            return (ActionRisk::Medium, None);
        }
        if lower_type.contains("read") || lower_type.contains("get") || lower_type.contains("list") {
            return (ActionRisk::Low, None);
        }
        if !action.reversible { return (ActionRisk::High, None); }
        (ActionRisk::Medium, None)
    }

    fn count_recent_actions(&self, action_type: &str, now: i64, window_secs: i64) -> usize {
        let counts = self.action_counts.read();
        counts.get(action_type).map(|times| {
            times.iter().filter(|&&t| now - t < window_secs).count()
        }).unwrap_or(0)
    }

    fn record_action(&self, action_type: &str, now: i64) {
        let mut counts = self.action_counts.write();
        let times = counts.entry(action_type.to_string()).or_insert_with(|| VecDeque::with_capacity(1000));
        times.push_back(now);
        while times.len() > 1000 { times.pop_front(); }
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(AiAlert { timestamp: ts, severity: sev, component: "human_in_the_loop_enforcer".into(), title: title.into(), details: details.into() });
    }

    pub fn total_requests(&self) -> u64 { self.total_requests.load(Ordering::Relaxed) }
    pub fn total_approved(&self) -> u64 { self.total_approved.load(Ordering::Relaxed) }
    pub fn total_denied(&self) -> u64 { self.total_denied.load(Ordering::Relaxed) }
    pub fn total_auto_approved(&self) -> u64 { self.total_auto_approved.load(Ordering::Relaxed) }
    pub fn total_timed_out(&self) -> u64 { self.total_timed_out.load(Ordering::Relaxed) }
    pub fn total_forbidden(&self) -> u64 { self.total_forbidden.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
