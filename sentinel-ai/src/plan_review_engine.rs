//! Plan Review Engine — pre-flight security analysis for AI agent plans.
//!
//! When an AI agent (Claude Code, Cursor, Devin, etc.) proposes a plan,
//! this engine analyzes every step BEFORE execution:
//!
//! - **Risk classification** per step (Low / Medium / High / Critical)
//! - **Trajectory analysis** detecting suspicious multi-step chains
//! - **Goal–step alignment** flagging steps that don't match the stated objective
//! - **Blast radius assessment** for credential and network exposure
//! - **Smart recommendations** with safer alternatives
//! - **Approval memory** learning user patterns to reduce friction
//! - **Non-blocking** auto-approves LOW, flags MEDIUM, pauses on HIGH/CRITICAL
//! - **MITRE ATT&CK mapping** per plan action for enterprise threat intelligence
//!
//! Integration: MCP server or local HTTP API at localhost:7700
//!
//! Memory breakthroughs:
//!   #2  TieredCache — hot/warm/cold verdict cache for repeated plan patterns
//!   #461 DifferentialStore — approval pattern evolution tracking
//!   #5  StreamAccumulator — streaming review statistics aggregation
//!   #569 PruningMap — φ-weighted review history eviction
//!   #1  HierarchicalState — O(log n) risk trend checkpointing
//!   #627 SparseMatrix — sparse agent×action risk matrix
//!   #592 DedupStore — content-addressed plan fingerprint dedup
//!   #6  MemoryMetrics — verified memory budget tracking

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::differential::DifferentialStore;
use sentinel_core::streaming::StreamAccumulator;
use sentinel_core::pruning::PruningMap;
use sentinel_core::hierarchical::HierarchicalState;
use sentinel_core::sparse::SparseMatrix;
use sentinel_core::dedup::DedupStore;
use sentinel_core::MemoryMetrics;
use parking_lot::RwLock;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::time::Duration;
use tracing::info;

const MAX_ALERTS: usize = 5_000;
const MAX_REVIEW_HISTORY: usize = 10_000;

// ── Plan Actions ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum PlanAction {
    // File system
    FileRead, FileWrite, FileDelete, FileCreate, DirectoryCreate,
    // Commands & processes
    CommandExec, ShellSpawn, ScriptExecute, SudoExec,
    // Network
    NetworkOutbound, NetworkListen, PortOpen, DnsModify,
    // Credentials & secrets
    CredentialAccess, CredentialStore, SecretRead, OAuthFlow,
    // Communication
    EmailAccess, EmailSend, SlackPost, WebhookCall,
    // Code & version control
    GitCommit, GitPush, GitClone, CodeModify, PackageInstall,
    // Browser & API
    BrowserNavigate, ApiCall, DatabaseAccess,
    // System
    SystemModify, EnvironmentWrite, CronModify, ServiceRestart,
}

impl PlanAction {
    /// Map to MITRE ATT&CK technique IDs for enterprise threat intelligence.
    pub fn mitre_techniques(&self) -> &'static [&'static str] {
        match self {
            Self::FileRead => &["T1005"],           // Data from Local System
            Self::FileWrite | Self::FileCreate => &["T1565.001"],  // Stored Data Manipulation
            Self::FileDelete => &["T1070.004"],     // File Deletion (indicator removal)
            Self::DirectoryCreate => &["T1074.001"],// Local Data Staging
            Self::CommandExec | Self::ShellSpawn => &["T1059"],    // Command and Scripting
            Self::ScriptExecute => &["T1059.004"],  // Unix Shell
            Self::SudoExec => &["T1548.003"],       // Sudo and Sudo Caching
            Self::NetworkOutbound => &["T1071"],    // Application Layer Protocol
            Self::NetworkListen => &["T1571"],      // Non-Standard Port
            Self::PortOpen => &["T1090"],           // Proxy
            Self::DnsModify => &["T1584.001"],      // Domains
            Self::CredentialAccess | Self::SecretRead => &["T1552"], // Unsecured Credentials
            Self::CredentialStore => &["T1555"],    // Credentials from Password Stores
            Self::OAuthFlow => &["T1550.001"],      // Application Access Token
            Self::EmailAccess | Self::EmailSend => &["T1114"],     // Email Collection
            Self::SlackPost => &["T1530"],          // Data from Cloud Storage
            Self::WebhookCall => &["T1567"],        // Exfiltration Over Web Service
            Self::GitCommit | Self::GitPush => &["T1213.003"],     // Code Repositories
            Self::GitClone => &["T1213.003"],       // Code Repositories
            Self::CodeModify => &["T1195.002"],     // Supply Chain Compromise
            Self::PackageInstall => &["T1195.001"], // Compromise Software Dependencies
            Self::BrowserNavigate => &["T1185"],    // Browser Session Hijacking
            Self::ApiCall => &["T1106"],            // Native API
            Self::DatabaseAccess => &["T1213"],     // Data from Information Repositories
            Self::SystemModify => &["T1543"],       // Create or Modify System Process
            Self::EnvironmentWrite => &["T1480"],   // Execution Guardrails
            Self::CronModify => &["T1053.003"],     // Cron
            Self::ServiceRestart => &["T1489"],     // Service Stop
        }
    }

    /// Inherent risk tier before any context is applied.
    pub fn base_risk(&self) -> RiskLevel {
        match self {
            // Always high
            Self::SudoExec | Self::CredentialAccess | Self::CredentialStore
            | Self::SecretRead | Self::OAuthFlow | Self::DnsModify
            | Self::SystemModify | Self::CronModify | Self::ServiceRestart
            | Self::EmailSend | Self::NetworkListen | Self::PortOpen => RiskLevel::High,

            // Medium by default
            Self::CommandExec | Self::ShellSpawn | Self::ScriptExecute
            | Self::NetworkOutbound | Self::GitPush | Self::PackageInstall
            | Self::DatabaseAccess | Self::EnvironmentWrite
            | Self::EmailAccess | Self::WebhookCall
            | Self::FileDelete | Self::SlackPost => RiskLevel::Medium,

            // Low by default
            Self::FileRead | Self::FileWrite | Self::FileCreate
            | Self::DirectoryCreate | Self::CodeModify
            | Self::GitCommit | Self::GitClone
            | Self::BrowserNavigate | Self::ApiCall => RiskLevel::Low,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub enum RiskLevel { Low, Medium, High, Critical }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ApprovalStatus { Pending, AutoApproved, Approved, Denied, NeedsJustification }

// ── Plan Data Model ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PlanStep {
    pub step_number: u32,
    pub action: PlanAction,
    pub target: String,
    pub description: String,
    pub requires_credential: Option<String>,
    pub network_endpoint: Option<String>,
    pub network_port: Option<u16>,
    pub estimated_duration_ms: Option<u64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentPlan {
    pub plan_id: String,
    pub agent_name: String,
    pub stated_goal: String,
    pub steps: Vec<PlanStep>,
    pub submitted_at: i64,
}

// ── Review Results ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StepReview {
    pub step_number: u32,
    pub risk_level: RiskLevel,
    pub risk_reasons: Vec<String>,
    pub recommendation: String,
    pub alternatives: Vec<String>,
    pub approval: ApprovalStatus,
    pub blast_radius: Option<String>,
    pub goal_aligned: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChainWarning {
    pub chain_name: String,
    pub steps_involved: Vec<u32>,
    pub severity: Severity,
    pub description: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PlanReview {
    pub plan_id: String,
    pub agent_name: String,
    pub overall_risk: RiskLevel,
    pub step_reviews: Vec<StepReview>,
    pub chain_warnings: Vec<ChainWarning>,
    pub trajectory_summary: String,
    pub auto_approved_count: u32,
    pub needs_approval_count: u32,
    pub denied_count: u32,
    pub reviewed_at: i64,
}

// ── Sensitive Targets & Dangerous Patterns ───────────────────────────────────

const SENSITIVE_PATHS: &[&str] = &[
    ".ssh/", "id_rsa", "id_ed25519", ".gnupg/", ".aws/credentials",
    ".env", ".env.local", ".env.production", "secrets.", "credentials.",
    "password", "token", ".npmrc", ".pypirc", ".docker/config.json",
    "shadow", "passwd", "sudoers", "authorized_keys", "known_hosts",
    ".git-credentials", ".netrc", "keychain", "keystore", "vault",
    "private_key", "secret_key", ".pgpass", "wallet.dat", "seed_phrase",
    "mnemonic", "recovery_key", "master_key", "encryption_key",
    "/etc/ssl/private", "ca-certificates", ".pem", ".p12",
    "kubeconfig", ".kube/config", "terraform.tfstate",
];

const DANGEROUS_COMMANDS: &[&str] = &[
    "rm -rf", "rm -r /", "chmod 777", "chmod -R 777",
    "curl | bash", "curl | sh", "wget | bash", "wget | sh",
    "eval(", "exec(", "sudo rm", "sudo chmod",
    "dd if=", "mkfs.", "fdisk", "iptables -F", "ufw disable",
    "kill -9", "killall", "nc -l", "netcat",
    "git push --force", "git reset --hard",
    "DROP DATABASE", "DROP TABLE", "TRUNCATE TABLE",
    "docker run --privileged", "docker run -v /:/",
];

/// Credential blast radius: if compromised, what's the damage?
const CREDENTIAL_BLAST_RADIUS: &[(&str, &str, &str)] = &[
    ("gmail", "Critical", "Full access to email, contacts, drive. Can reset passwords for other services."),
    ("google", "Critical", "Access to entire Google Workspace. Lateral movement to all Google services."),
    ("aws", "Critical", "Full cloud infrastructure access. Can spin up resources, access S3, modify IAM."),
    ("github", "High", "Access to all repositories, can push malicious code, modify CI/CD pipelines."),
    ("gitlab", "High", "Repository access plus CI/CD pipeline control."),
    ("ssh", "Critical", "Remote shell access to servers. Can pivot to any connected infrastructure."),
    ("dns", "High", "Can redirect your domain to malicious servers. Email interception possible."),
    ("database", "High", "Direct access to application data. PII exposure risk."),
    ("docker", "High", "Container escape possible. Host filesystem access with privileged mode."),
    ("kubernetes", "Critical", "Full cluster control. Can access all pods, secrets, and namespaces."),
    ("slack", "Medium", "Can post as you, read private channels, access shared files."),
    ("stripe", "Critical", "Payment processing access. Financial fraud risk."),
    ("twilio", "Medium", "Can send SMS/calls as your account. Social engineering vector."),
    ("openai", "Low", "API usage charges. Prompt history exposure."),
    ("anthropic", "Low", "API usage charges. Conversation history exposure."),
    ("npm", "High", "Can publish malicious packages under your name. Supply chain attack."),
    ("pypi", "High", "Can publish malicious Python packages. Supply chain attack."),
    ("vercel", "Medium", "Can deploy malicious sites under your domain."),
    ("netlify", "Medium", "Can deploy malicious sites under your domain."),
    ("cloudflare", "High", "DNS + CDN control. Can intercept all traffic to your domains."),
];

/// Goal keywords mapped to expected action types — for goal-step alignment.
const GOAL_ACTION_MAP: &[(&str, &[PlanAction])] = &[
    ("deploy", &[PlanAction::FileRead, PlanAction::CommandExec, PlanAction::GitPush,
                  PlanAction::ApiCall, PlanAction::NetworkOutbound, PlanAction::EnvironmentWrite]),
    ("test", &[PlanAction::FileRead, PlanAction::CommandExec, PlanAction::FileWrite]),
    ("refactor", &[PlanAction::FileRead, PlanAction::FileWrite, PlanAction::CodeModify, PlanAction::GitCommit]),
    ("review", &[PlanAction::FileRead, PlanAction::CodeModify, PlanAction::GitCommit]),
    ("build", &[PlanAction::FileRead, PlanAction::CommandExec, PlanAction::FileWrite, PlanAction::PackageInstall]),
    ("email", &[PlanAction::EmailAccess, PlanAction::EmailSend]),
    ("dns", &[PlanAction::DnsModify, PlanAction::ApiCall, PlanAction::CredentialAccess]),
    ("database", &[PlanAction::DatabaseAccess, PlanAction::ApiCall]),
    ("setup", &[PlanAction::FileCreate, PlanAction::DirectoryCreate, PlanAction::PackageInstall,
                 PlanAction::CommandExec, PlanAction::EnvironmentWrite]),
    ("install", &[PlanAction::PackageInstall, PlanAction::CommandExec, PlanAction::FileWrite]),
    ("debug", &[PlanAction::FileRead, PlanAction::CommandExec, PlanAction::FileWrite]),
    ("fix", &[PlanAction::FileRead, PlanAction::FileWrite, PlanAction::CodeModify,
              PlanAction::CommandExec, PlanAction::GitCommit]),
];

/// Suspicious multi-step chain patterns in plans.
struct PlanChainPattern {
    name: &'static str,
    actions: &'static [PlanAction],
    severity: Severity,
    description: &'static str,
}

const PLAN_CHAIN_PATTERNS: &[PlanChainPattern] = &[
    PlanChainPattern {
        name: "credential-then-exfiltrate",
        actions: &[PlanAction::CredentialAccess, PlanAction::NetworkOutbound],
        severity: Severity::Critical,
        description: "Plan reads credentials then makes network requests — potential exfiltration.",
    },
    PlanChainPattern {
        name: "secret-read-then-send",
        actions: &[PlanAction::SecretRead, PlanAction::EmailSend],
        severity: Severity::Critical,
        description: "Plan reads secrets then sends email — credentials may be leaked.",
    },
    PlanChainPattern {
        name: "port-open-then-listen",
        actions: &[PlanAction::PortOpen, PlanAction::NetworkListen],
        severity: Severity::High,
        description: "Plan opens a port and listens — creates inbound attack surface.",
    },
    PlanChainPattern {
        name: "clone-modify-push",
        actions: &[PlanAction::GitClone, PlanAction::CodeModify, PlanAction::GitPush],
        severity: Severity::High,
        description: "Plan clones a repo, modifies code, and pushes — supply chain injection risk.",
    },
    PlanChainPattern {
        name: "package-install-exec",
        actions: &[PlanAction::PackageInstall, PlanAction::CommandExec],
        severity: Severity::High,
        description: "Plan installs packages then executes commands — dependency attack vector.",
    },
    PlanChainPattern {
        name: "env-read-then-network",
        actions: &[PlanAction::SecretRead, PlanAction::NetworkOutbound],
        severity: Severity::Critical,
        description: "Plan reads environment secrets then contacts network — secret exfiltration.",
    },
    PlanChainPattern {
        name: "dns-modify-then-deploy",
        actions: &[PlanAction::DnsModify, PlanAction::NetworkOutbound],
        severity: Severity::High,
        description: "Plan modifies DNS then makes network calls — domain hijack risk.",
    },
    PlanChainPattern {
        name: "sudo-then-cron",
        actions: &[PlanAction::SudoExec, PlanAction::CronModify],
        severity: Severity::Critical,
        description: "Plan uses sudo then modifies cron — persistence mechanism.",
    },
    PlanChainPattern {
        name: "file-read-then-webhook",
        actions: &[PlanAction::FileRead, PlanAction::WebhookCall],
        severity: Severity::High,
        description: "Plan reads files then calls webhooks — data exfiltration via webhook.",
    },
    PlanChainPattern {
        name: "oauth-then-email",
        actions: &[PlanAction::OAuthFlow, PlanAction::EmailSend],
        severity: Severity::High,
        description: "Plan acquires OAuth tokens then sends email — impersonation risk.",
    },
];

// ── Approval Memory ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ApprovalPattern {
    agent_name: String,
    action: PlanAction,
    target_pattern: String,
    approved_count: u32,
    denied_count: u32,
    last_approved: i64,
}

// ── Review Statistics (for StreamAccumulator) ────────────────────────────────

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ReviewStats {
    pub total_reviews: u64,
    pub total_steps_reviewed: u64,
    pub auto_approved_total: u64,
    pub denied_total: u64,
    pub critical_total: u64,
    pub high_total: u64,
    pub chain_detections_total: u64,
    pub goal_misaligned_total: u64,
    pub unique_agents: HashSet<String>,
    pub window_start: i64,
    pub window_end: i64,
}

// ── The Engine ───────────────────────────────────────────────────────────────

pub struct PlanReviewEngine {
    approval_memory: RwLock<Vec<ApprovalPattern>>,
    // Counters & state
    alerts: RwLock<Vec<AiAlert>>,
    total_reviews: AtomicU64,
    total_denied: AtomicU64,
    total_critical: AtomicU64,
    auto_approve_threshold: u32,
    enabled: AtomicBool,
    // ── Memory Breakthroughs ─────────────────────────────────────────────
    /// Breakthrough #2: Hot/warm/cold verdict cache for repeated plan patterns
    verdict_cache: TieredCache<String, RiskLevel>,
    /// Breakthrough #461: Approval pattern evolution tracking
    approval_diffs: RwLock<DifferentialStore<String, String>>,
    /// Breakthrough #5: Streaming review statistics aggregation
    review_stats: RwLock<StreamAccumulator<PlanReview, ReviewStats>>,
    /// Breakthrough #569: φ-weighted review history eviction
    review_history: RwLock<PruningMap<String, PlanReview>>,
    /// Breakthrough #1: O(log n) risk trend checkpointing
    risk_checkpoints: RwLock<HierarchicalState<u64>>,
    /// Breakthrough #627: Sparse agent×action risk matrix
    risk_matrix: RwLock<SparseMatrix<String, String, u64>>,
    /// Breakthrough #592: Content-addressed plan fingerprint dedup
    plan_dedup: RwLock<DedupStore<String, String>>,
    /// Breakthrough #6: Verified memory budget tracking
    metrics: Option<MemoryMetrics>,
}

impl PlanReviewEngine {
    pub fn new() -> Self {
        let stats_acc = StreamAccumulator::new(25, ReviewStats::default(), |acc, reviews: &[PlanReview]| {
            for r in reviews {
                acc.total_reviews += 1;
                acc.total_steps_reviewed += r.step_reviews.len() as u64;
                acc.auto_approved_total += r.auto_approved_count as u64;
                acc.denied_total += r.denied_count as u64;
                acc.chain_detections_total += r.chain_warnings.len() as u64;
                acc.unique_agents.insert(r.agent_name.clone());
                for sr in &r.step_reviews {
                    match sr.risk_level {
                        RiskLevel::Critical => acc.critical_total += 1,
                        RiskLevel::High => acc.high_total += 1,
                        _ => {}
                    }
                    if !sr.goal_aligned { acc.goal_misaligned_total += 1; }
                }
                if acc.window_start == 0 || r.reviewed_at < acc.window_start { acc.window_start = r.reviewed_at; }
                if r.reviewed_at > acc.window_end { acc.window_end = r.reviewed_at; }
            }
        });

        Self {
            approval_memory: RwLock::new(Vec::new()),
            alerts: RwLock::new(Vec::new()),
            total_reviews: AtomicU64::new(0),
            total_denied: AtomicU64::new(0),
            total_critical: AtomicU64::new(0),
            auto_approve_threshold: 3,
            enabled: AtomicBool::new(true),
            verdict_cache: TieredCache::new(2_000),
            approval_diffs: RwLock::new(DifferentialStore::new()),
            review_stats: RwLock::new(stats_acc),
            review_history: RwLock::new(PruningMap::new(MAX_REVIEW_HISTORY).with_ttl(Duration::from_secs(86_400))),
            risk_checkpoints: RwLock::new(HierarchicalState::new(8, 64)),
            risk_matrix: RwLock::new(SparseMatrix::new(0)),
            plan_dedup: RwLock::new(DedupStore::new()),
            metrics: None,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("plan_review_engine", 4 * 1024 * 1024);
        self.verdict_cache = self.verdict_cache.with_metrics(metrics.clone(), "plan_review_engine");
        self.metrics = Some(metrics);
        self
    }

    // ── Main entry point ─────────────────────────────────────────────────

    /// Review an agent's plan. Returns a full risk analysis with per-step
    /// reviews, chain warnings, trajectory analysis, and approval statuses.
    pub fn review_plan(&self, plan: &AgentPlan) -> PlanReview {
        if !self.enabled.load(Ordering::Relaxed) {
            return PlanReview {
                plan_id: plan.plan_id.clone(), agent_name: plan.agent_name.clone(),
                overall_risk: RiskLevel::Low, step_reviews: Vec::new(),
                chain_warnings: Vec::new(), trajectory_summary: "Engine disabled".into(),
                auto_approved_count: plan.steps.len() as u32,
                needs_approval_count: 0, denied_count: 0,
                reviewed_at: chrono::Utc::now().timestamp(),
            };
        }

        let now = chrono::Utc::now().timestamp();
        self.total_reviews.fetch_add(1, Ordering::Relaxed);

        // Breakthrough #592: Dedup — fingerprint the plan to detect duplicates
        let plan_fingerprint = format!("{}:{}:{}", plan.agent_name, plan.stated_goal,
            plan.steps.iter().map(|s| format!("{:?}:{}", s.action, s.target)).collect::<Vec<_>>().join("|"));
        self.plan_dedup.write().insert(plan.plan_id.clone(), plan_fingerprint);

        // 1. Classify each step
        let mut step_reviews: Vec<StepReview> = plan.steps.iter()
            .map(|step| self.review_step(step, &plan.stated_goal, &plan.agent_name))
            .collect();

        // 2. Detect suspicious multi-step chains across the full trajectory
        let chain_warnings = self.detect_chains(&plan.steps);

        // 3. Escalate risk for steps involved in chain warnings
        for warning in &chain_warnings {
            for &step_num in &warning.steps_involved {
                if let Some(review) = step_reviews.iter_mut().find(|r| r.step_number == step_num) {
                    if warning.severity >= Severity::High && review.risk_level < RiskLevel::High {
                        review.risk_level = RiskLevel::High;
                        review.risk_reasons.push(format!(
                            "Escalated: part of '{}' chain — {}",
                            warning.chain_name, warning.description
                        ));
                        review.approval = ApprovalStatus::Pending;
                    }
                }
            }
        }

        // 4. Compute stats
        let auto_approved_count = step_reviews.iter()
            .filter(|r| r.approval == ApprovalStatus::AutoApproved).count() as u32;
        let needs_approval_count = step_reviews.iter()
            .filter(|r| matches!(r.approval, ApprovalStatus::Pending | ApprovalStatus::NeedsJustification))
            .count() as u32;
        let denied_count = step_reviews.iter()
            .filter(|r| r.approval == ApprovalStatus::Denied).count() as u32;

        // 5. Overall risk = highest step risk
        let overall_risk = step_reviews.iter()
            .map(|r| r.risk_level)
            .max()
            .unwrap_or(RiskLevel::Low);

        // 6. Generate trajectory summary
        let trajectory_summary = self.summarize_trajectory(
            plan, &step_reviews, &chain_warnings,
            auto_approved_count, needs_approval_count,
        );

        let review = PlanReview {
            plan_id: plan.plan_id.clone(),
            agent_name: plan.agent_name.clone(),
            overall_risk,
            step_reviews,
            chain_warnings,
            trajectory_summary,
            auto_approved_count,
            needs_approval_count,
            denied_count,
            reviewed_at: now,
        };

        // Breakthrough #627: Update sparse agent×action risk matrix
        {
            let mut matrix = self.risk_matrix.write();
            for sr in &review.step_reviews {
                let action_key = format!("{:?}", plan.steps.get(sr.step_number as usize).map(|s| s.action).unwrap_or(PlanAction::FileRead));
                let current = *matrix.get(&plan.agent_name, &action_key);
                matrix.set(plan.agent_name.clone(), action_key, current + 1);
            }
        }

        // Breakthrough #1: Checkpoint risk trend
        {
            let mut checkpoints = self.risk_checkpoints.write();
            checkpoints.checkpoint(overall_risk as u64);
        }

        // Breakthrough #2: Cache verdict for this plan pattern
        {
            let cache_key = format!("{}:{}", plan.agent_name, plan.stated_goal);
            self.verdict_cache.insert(cache_key, overall_risk);
        }

        // Breakthrough #569: Store in φ-weighted pruning history
        self.review_history.write().insert(plan.plan_id.clone(), review.clone());

        // Breakthrough #461: Track approval evolution diffs
        self.approval_diffs.write().record_insert(
            plan.agent_name.clone(),
            format!("review:{} risk:{:?} auto:{} pending:{}", plan.plan_id, overall_risk, auto_approved_count, needs_approval_count),
        );

        // Generate alerts for high/critical plans
        if overall_risk >= RiskLevel::High {
            let severity = if overall_risk == RiskLevel::Critical { Severity::Critical } else { Severity::High };
            self.add_alert(now, severity,
                &format!("{} submitted {:?} risk plan", plan.agent_name, overall_risk),
                &review.trajectory_summary);
            if overall_risk == RiskLevel::Critical {
                self.total_critical.fetch_add(1, Ordering::Relaxed);
            }
        }

        info!(plan_id = %plan.plan_id, agent = %plan.agent_name,
              overall = ?review.overall_risk,
              auto = auto_approved_count, pending = needs_approval_count,
              "Plan reviewed: {} steps", plan.steps.len());

        review
    }

    fn add_alert(&self, timestamp: i64, severity: Severity, title: &str, details: &str) {
        let mut alerts = self.alerts.write();
        if alerts.len() >= MAX_ALERTS { alerts.drain(..MAX_ALERTS / 2); }
        alerts.push(AiAlert {
            timestamp, severity, component: "plan_review_engine".into(),
            title: title.into(), details: details.into(),
        });
    }

    // ── Per-Step Analysis ────────────────────────────────────────────────

    fn review_step(&self, step: &PlanStep, stated_goal: &str, agent_name: &str) -> StepReview {
        let mut risk_level = step.action.base_risk();
        let mut risk_reasons: Vec<String> = Vec::new();
        let mut alternatives: Vec<String> = Vec::new();
        let mut blast_radius: Option<String> = None;
        let target_lower = step.target.to_lowercase();
        let desc_lower = step.description.to_lowercase();

        // ── Sensitive path escalation ────────────────────────────────────
        if matches!(step.action, PlanAction::FileRead | PlanAction::FileWrite
            | PlanAction::FileDelete | PlanAction::FileCreate | PlanAction::CodeModify)
        {
            for &sensitive in SENSITIVE_PATHS {
                if target_lower.contains(sensitive) {
                    risk_level = RiskLevel::Critical;
                    risk_reasons.push(format!(
                        "Targets sensitive path '{}' — contains credentials or secrets", sensitive
                    ));
                    alternatives.push("Consider using a secrets manager instead of direct file access.".into());
                    break;
                }
            }
        }

        // ── Dangerous command escalation ─────────────────────────────────
        if matches!(step.action, PlanAction::CommandExec | PlanAction::ShellSpawn
            | PlanAction::ScriptExecute | PlanAction::SudoExec)
        {
            for &cmd in DANGEROUS_COMMANDS {
                if desc_lower.contains(&cmd.to_lowercase()) || target_lower.contains(&cmd.to_lowercase()) {
                    risk_level = RiskLevel::Critical;
                    risk_reasons.push(format!(
                        "Contains dangerous command pattern: '{}'", cmd
                    ));
                    break;
                }
            }
        }

        // ── Credential blast radius ──────────────────────────────────────
        if step.requires_credential.is_some() || matches!(step.action,
            PlanAction::CredentialAccess | PlanAction::CredentialStore
            | PlanAction::SecretRead | PlanAction::OAuthFlow)
        {
            let cred = step.requires_credential.as_deref().unwrap_or(&step.target);
            let cred_lower = cred.to_lowercase();
            for &(pattern, severity, impact) in CREDENTIAL_BLAST_RADIUS {
                if cred_lower.contains(pattern) || target_lower.contains(pattern) {
                    risk_reasons.push(format!("Credential blast radius ({}): {}", severity, impact));
                    blast_radius = Some(format!("{}: {}", severity, impact));
                    if severity == "Critical" {
                        risk_level = RiskLevel::Critical;
                    }
                    break;
                }
            }
        }

        // ── Network exposure ─────────────────────────────────────────────
        if matches!(step.action, PlanAction::NetworkListen | PlanAction::PortOpen) {
            risk_reasons.push("Opens your machine to inbound connections.".into());
            alternatives.push("Use a reverse proxy or SSH tunnel instead of exposing ports directly.".into());
            if let Some(port) = step.network_port {
                if port < 1024 {
                    risk_level = RiskLevel::Critical;
                    risk_reasons.push(format!("Privileged port {} — requires root and is highly visible.", port));
                }
            }
        }

        if matches!(step.action, PlanAction::NetworkOutbound) {
            if let Some(ref endpoint) = step.network_endpoint {
                let ep_lower = endpoint.to_lowercase();
                if ep_lower.contains("pastebin") || ep_lower.contains("requestbin")
                    || ep_lower.contains("ngrok") || ep_lower.contains("webhook.site")
                    || ep_lower.contains("burpcollaborator")
                {
                    risk_level = RiskLevel::Critical;
                    risk_reasons.push(format!(
                        "Suspicious endpoint '{}' — commonly used for data exfiltration.", endpoint
                    ));
                }
            }
        }

        // ── Goal–step alignment ──────────────────────────────────────────
        let goal_aligned = self.check_goal_alignment(step, stated_goal);
        if !goal_aligned {
            if risk_level < RiskLevel::High {
                risk_level = RiskLevel::High;
            }
            risk_reasons.push(format!(
                "This action ({:?}) seems unrelated to the stated goal: '{}'",
                step.action, stated_goal
            ));
        }

        // ── Generate recommendation ──────────────────────────────────────
        let recommendation = self.generate_recommendation(step, &risk_reasons, risk_level, stated_goal);

        // ── Auto-approval check ──────────────────────────────────────────
        let approval = if risk_level <= RiskLevel::Low {
            if self.has_prior_approval(agent_name, step.action, &step.target) {
                ApprovalStatus::AutoApproved
            } else {
                ApprovalStatus::AutoApproved  // LOW = always auto-approve
            }
        } else if risk_level == RiskLevel::Medium {
            if self.has_prior_approval(agent_name, step.action, &step.target) {
                ApprovalStatus::AutoApproved
            } else {
                ApprovalStatus::Pending
            }
        } else if risk_level == RiskLevel::Critical {
            ApprovalStatus::NeedsJustification
        } else {
            ApprovalStatus::Pending
        };

        // If no reasons were generated, add a default
        if risk_reasons.is_empty() {
            risk_reasons.push(format!("{:?} action — base risk: {:?}", step.action, risk_level));
        }

        StepReview {
            step_number: step.step_number,
            risk_level,
            risk_reasons,
            recommendation,
            alternatives,
            approval,
            blast_radius,
            goal_aligned,
        }
    }

    // ── Goal Alignment ───────────────────────────────────────────────────

    fn check_goal_alignment(&self, step: &PlanStep, goal: &str) -> bool {
        let goal_lower = goal.to_lowercase();

        // Find which goal category matches
        for &(keyword, expected_actions) in GOAL_ACTION_MAP {
            if goal_lower.contains(keyword) {
                // If the goal matches a known category, check if this action is expected
                if expected_actions.contains(&step.action) {
                    return true;
                }
                // Some actions are always acceptable regardless of goal
                if matches!(step.action, PlanAction::FileRead | PlanAction::DirectoryCreate) {
                    return true;
                }
                return false;
            }
        }

        // Unknown goal — can't determine alignment, assume aligned
        true
    }

    // ── Chain Detection ──────────────────────────────────────────────────

    fn detect_chains(&self, steps: &[PlanStep]) -> Vec<ChainWarning> {
        let mut warnings = Vec::new();
        let actions: Vec<(u32, PlanAction)> = steps.iter()
            .map(|s| (s.step_number, s.action))
            .collect();

        for pattern in PLAN_CHAIN_PATTERNS {
            // Sliding window: find if pattern actions appear in order
            let mut pattern_idx = 0;
            let mut matched_steps = Vec::new();

            for &(step_num, action) in &actions {
                if pattern_idx < pattern.actions.len() && action == pattern.actions[pattern_idx] {
                    matched_steps.push(step_num);
                    pattern_idx += 1;
                }
            }

            if pattern_idx == pattern.actions.len() {
                warnings.push(ChainWarning {
                    chain_name: pattern.name.to_string(),
                    steps_involved: matched_steps,
                    severity: pattern.severity,
                    description: pattern.description.to_string(),
                });
            }
        }

        warnings
    }

    // ── Recommendation Generator ─────────────────────────────────────────

    fn generate_recommendation(&self, step: &PlanStep, reasons: &[String],
                                risk: RiskLevel, goal: &str) -> String {
        match risk {
            RiskLevel::Low => format!(
                "Low risk. {} is routine for '{}'.",
                step.description, goal
            ),
            RiskLevel::Medium => {
                if matches!(step.action, PlanAction::PackageInstall) {
                    format!(
                        "Review the packages being installed. Consider pinning versions \
                         and checking for known vulnerabilities before approving."
                    )
                } else if matches!(step.action, PlanAction::GitPush) {
                    format!(
                        "Verify the target branch and remote. Consider reviewing the diff \
                         before allowing the push."
                    )
                } else if matches!(step.action, PlanAction::NetworkOutbound) {
                    format!(
                        "Verify the destination endpoint is expected for this task. \
                         Check that no sensitive data is included in the request."
                    )
                } else {
                    format!("Medium risk. Review before approving: {}", step.description)
                }
            },
            RiskLevel::High => {
                if matches!(step.action, PlanAction::NetworkListen | PlanAction::PortOpen) {
                    format!(
                        "CAUTION: This opens your machine to inbound traffic. \
                         Ask yourself: does '{}' really need an open port? \
                         Consider a reverse proxy or SSH tunnel instead.", goal
                    )
                } else if matches!(step.action, PlanAction::CredentialAccess
                    | PlanAction::OAuthFlow | PlanAction::SecretRead) {
                    format!(
                        "HIGH RISK: Agent requests access to credentials. \
                         Verify this is essential for '{}'. Consider providing \
                         a scoped API key with minimal permissions instead of \
                         full credentials.", goal
                    )
                } else if matches!(step.action, PlanAction::DnsModify) {
                    format!(
                        "HIGH RISK: DNS changes can redirect your domain. \
                         Double-check the target records match your intended \
                         configuration. DNS changes propagate globally."
                    )
                } else {
                    format!("High risk action. Carefully review: {}", reasons.first().map(|s| s.as_str()).unwrap_or(""))
                }
            },
            RiskLevel::Critical => {
                format!(
                    "CRITICAL: This step requires explicit justification from the agent. \
                     Ask why {:?} is necessary for '{}'. {}",
                    step.action, goal,
                    reasons.first().map(|s| s.as_str()).unwrap_or("")
                )
            },
        }
    }

    // ── Approval Memory ──────────────────────────────────────────────────

    fn has_prior_approval(&self, agent: &str, action: PlanAction, target: &str) -> bool {
        let memory = self.approval_memory.read();
        memory.iter().any(|pat| {
            pat.agent_name == agent
            && pat.action == action
            && target.contains(&pat.target_pattern)
            && pat.approved_count >= self.auto_approve_threshold
            && pat.denied_count == 0
        })
    }

    /// Record that a user approved or denied a step — the engine learns.
    pub fn record_approval(&self, agent: &str, action: PlanAction, target: &str, approved: bool) {
        let now = chrono::Utc::now().timestamp();
        let mut memory = self.approval_memory.write();

        // Normalize target to a pattern (use parent directory for files)
        let pattern = if target.contains('/') {
            target.rsplitn(2, '/').last().unwrap_or(target).to_string()
        } else {
            target.to_string()
        };

        if let Some(existing) = memory.iter_mut().find(|p| {
            p.agent_name == agent && p.action == action && p.target_pattern == pattern
        }) {
            if approved {
                existing.approved_count += 1;
                existing.last_approved = now;
            } else {
                existing.denied_count += 1;
            }
        } else {
            memory.push(ApprovalPattern {
                agent_name: agent.to_string(),
                action,
                target_pattern: pattern,
                approved_count: if approved { 1 } else { 0 },
                denied_count: if approved { 0 } else { 1 },
                last_approved: if approved { now } else { 0 },
            });
        }
    }

    // ── Trajectory Summary ───────────────────────────────────────────────

    fn summarize_trajectory(&self, plan: &AgentPlan, reviews: &[StepReview],
                            chains: &[ChainWarning], auto: u32, pending: u32) -> String {
        let total = plan.steps.len();
        let critical = reviews.iter().filter(|r| r.risk_level == RiskLevel::Critical).count();
        let high = reviews.iter().filter(|r| r.risk_level == RiskLevel::High).count();
        let misaligned = reviews.iter().filter(|r| !r.goal_aligned).count();

        let mut summary = format!(
            "{} wants to execute {} steps for \"{}\".",
            plan.agent_name, total, plan.stated_goal
        );

        if critical > 0 {
            summary.push_str(&format!(
                " {} step(s) are CRITICAL RISK and require explicit justification.", critical
            ));
        }
        if high > 0 {
            summary.push_str(&format!(
                " {} step(s) are HIGH RISK and need your approval.", high
            ));
        }
        if misaligned > 0 {
            summary.push_str(&format!(
                " WARNING: {} step(s) don't appear to match the stated goal — investigate why.", misaligned
            ));
        }
        if !chains.is_empty() {
            let chain_names: Vec<&str> = chains.iter().map(|c| c.chain_name.as_str()).collect();
            summary.push_str(&format!(
                " Suspicious action chains detected: {}.", chain_names.join(", ")
            ));
        }
        if auto == total as u32 {
            summary.push_str(" All steps are low risk and auto-approved.");
        } else {
            summary.push_str(&format!(
                " {} auto-approved, {} awaiting your decision.", auto, pending
            ));
        }

        summary
    }

    // ── Public API ───────────────────────────────────────────────────────

    pub fn review_count(&self) -> u64 {
        self.total_reviews.load(Ordering::Relaxed)
    }

    pub fn denied_count(&self) -> u64 {
        self.total_denied.load(Ordering::Relaxed)
    }

    pub fn critical_count(&self) -> u64 {
        self.total_critical.load(Ordering::Relaxed)
    }

    pub fn recent_reviews(&self, limit: usize) -> Vec<PlanReview> {
        let hist = self.review_history.read();
        let mut reviews: Vec<PlanReview> = hist.iter().map(|(_, v)| v.clone()).collect();
        reviews.truncate(limit);
        reviews
    }

    pub fn set_auto_approve_threshold(&mut self, n: u32) {
        self.auto_approve_threshold = n;
    }

    pub fn set_enabled(&self, e: bool) {
        self.enabled.store(e, Ordering::Relaxed);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn approval_patterns(&self) -> Vec<(String, String, u32)> {
        self.approval_memory.read().iter()
            .map(|p| (p.agent_name.clone(), format!("{:?}:{}", p.action, p.target_pattern), p.approved_count))
            .collect()
    }

    /// Breakthrough #2: Look up a cached risk verdict for a known plan pattern.
    pub fn cached_verdict(&self, agent: &str, goal: &str) -> Option<RiskLevel> {
        let key = format!("{}:{}", agent, goal);
        self.verdict_cache.get(&key)
    }

    /// Breakthrough #5: Get streaming review statistics.
    pub fn review_statistics(&self) -> ReviewStats {
        self.review_stats.read().state().clone()
    }

    /// Breakthrough #627: Get the agent×action risk matrix as a list of (agent, action, count).
    pub fn risk_matrix_entries(&self) -> Vec<(String, String, u64)> {
        self.risk_matrix.read().iter()
            .map(|((r, c), v)| (r.clone(), c.clone(), *v))
            .collect()
    }

    /// Breakthrough #592: Check if a plan fingerprint has been seen before.
    pub fn is_duplicate_plan(&self, plan_id: &str) -> bool {
        self.plan_dedup.read().contains_key(&plan_id.to_string())
    }

    /// Alerts generated by the engine.
    pub fn alerts(&self) -> Vec<AiAlert> {
        self.alerts.read().clone()
    }

    /// Breakthrough #461: Get approval evolution diffs for an agent.
    pub fn approval_evolution(&self, agent: &str) -> Option<String> {
        self.approval_diffs.read().get(&agent.to_string())
    }

    /// Breakthrough #1: Get risk trend checkpoint count.
    pub fn risk_checkpoint_count(&self) -> usize {
        self.risk_checkpoints.read().total_checkpoints()
    }

    // ── Persistence ─────────────────────────────────────────────────────

    /// Save engine state to disk. Approval memory, counters, and alerts
    /// are preserved so learned patterns survive restarts.
    pub fn save_state(&self, path: &PathBuf) -> std::io::Result<()> {
        let state = PersistedState {
            approval_memory: self.approval_memory.read().clone(),
            alerts: self.alerts.read().clone(),
            total_reviews: self.total_reviews.load(Ordering::Relaxed),
            total_denied: self.total_denied.load(Ordering::Relaxed),
            total_critical: self.total_critical.load(Ordering::Relaxed),
            enabled: self.enabled.load(Ordering::Relaxed),
        };
        let json = serde_json::to_string_pretty(&state)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &json)?;
        std::fs::rename(&tmp, path)?;
        info!(path = %path.display(), approvals = state.approval_memory.len(),
              reviews = state.total_reviews, "State saved");
        Ok(())
    }

    /// Load previously persisted state from disk. Called once at startup.
    pub fn load_state(&self, path: &PathBuf) -> std::io::Result<()> {
        if !path.exists() {
            info!(path = %path.display(), "No persisted state found, starting fresh");
            return Ok(());
        }
        let json = std::fs::read_to_string(path)?;
        let state: PersistedState = serde_json::from_str(&json)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        *self.approval_memory.write() = state.approval_memory;
        *self.alerts.write() = state.alerts;
        self.total_reviews.store(state.total_reviews, Ordering::Relaxed);
        self.total_denied.store(state.total_denied, Ordering::Relaxed);
        self.total_critical.store(state.total_critical, Ordering::Relaxed);
        self.enabled.store(state.enabled, Ordering::Relaxed);
        info!(path = %path.display(), reviews = state.total_reviews, "State restored");
        Ok(())
    }
}

// ── Persisted State ─────────────────────────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedState {
    approval_memory: Vec<ApprovalPattern>,
    alerts: Vec<AiAlert>,
    total_reviews: u64,
    total_denied: u64,
    total_critical: u64,
    enabled: bool,
}
