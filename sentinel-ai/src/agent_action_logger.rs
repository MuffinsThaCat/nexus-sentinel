//! Agent Action Logger — immutable audit log of every AI agent action.
//!
//! Features:
//! - **40+ action types** covering every agent interaction surface
//! - **Contextual risk scoring** with sensitive path/command/pattern detection
//! - **Action chain analysis** detecting suspicious multi-step sequences
//! - **Rate anomaly detection** flagging sudden bursts of activity
//! - **Session forensics** with per-agent, per-session breakdowns
//! - **Sensitive target awareness** for SSH keys, env files, credentials, etc.
//!
//! Memory breakthroughs: #5 Streaming, #1 Hierarchical, #593 Compression, #569 Pruning, #6 Verifier

use crate::types::*;
use sentinel_core::streaming::StreamAccumulator;
use sentinel_core::hierarchical::HierarchicalState;
use sentinel_core::pruning::PruningMap;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

// ── Action types covering every agent interaction surface ───────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum AgentActionType {
    // File system (9)
    FileRead, FileWrite, FileDelete, FileMove, FileRename,
    FilePermissionChange, FileCreate, DirectoryCreate, DirectoryList,
    // Process & commands (7)
    CommandExec, ShellSpawn, ProcessSpawn, ProcessKill, ScriptExecute,
    SudoExec, CronModify,
    // Network (7)
    HttpRequest, HttpsRequest, WebSocketConnect, NetworkConnect,
    DnsLookup, SshConnect, FtpTransfer,
    // API & data (4)
    ApiCall, DatabaseQuery, DatabaseWrite, GraphqlQuery,
    // Application & browser (4)
    AppInteraction, BrowserNavigate, BrowserFormFill, BrowserDownload,
    // Clipboard & screen (4)
    ClipboardRead, ClipboardWrite, ScreenCapture, ScreenOcr,
    // Communication (5)
    MessageSend, EmailSend, EmailRead, SlackPost, DiscordPost,
    // Code & version control (5)
    GitCommit, GitPush, GitCheckout, GitClone, CodeModify,
    // System (6)
    RegistryModify, EnvironmentRead, EnvironmentWrite,
    PermissionChange, PackageInstall, CertificateAccess,
    // AI-specific (4)
    LlmApiCall, ToolUse, MemoryWrite, MemoryRead,
}

// ── Sensitive path patterns ─────────────────────────────────────────────────

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
    "application.properties", "appsettings.json",
];

const DANGEROUS_COMMANDS: &[&str] = &[
    "rm -rf", "rm -r /", "chmod 777", "chmod -R 777",
    "curl | bash", "curl | sh", "wget | bash", "wget | sh",
    "eval(", "exec(", "sudo rm", "sudo chmod",
    "dd if=", "mkfs.", "fdisk", "iptables -F", "ufw disable",
    "kill -9", "killall", "base64 -d", "base64 --decode",
    "nc -l", "netcat", "ncat",
    "git push --force", "git reset --hard",
    "DROP DATABASE", "DROP TABLE", "TRUNCATE TABLE",
    "docker run --privileged", "docker run -v /:/",
];

// ── Suspicious multi-step chains ────────────────────────────────────────────

struct ChainPattern {
    steps: &'static [AgentActionType],
    name: &'static str,
    severity: Severity,
}

const CHAIN_PATTERNS: &[ChainPattern] = &[
    ChainPattern { steps: &[AgentActionType::FileRead, AgentActionType::HttpRequest],
        name: "read-then-exfiltrate", severity: Severity::Critical },
    ChainPattern { steps: &[AgentActionType::EnvironmentRead, AgentActionType::HttpsRequest],
        name: "env-leak", severity: Severity::Critical },
    ChainPattern { steps: &[AgentActionType::SshConnect, AgentActionType::FileWrite],
        name: "remote-drop", severity: Severity::High },
    ChainPattern { steps: &[AgentActionType::GitClone, AgentActionType::CodeModify, AgentActionType::GitPush],
        name: "supply-chain-inject", severity: Severity::Critical },
    ChainPattern { steps: &[AgentActionType::DatabaseQuery, AgentActionType::FileWrite],
        name: "db-dump", severity: Severity::High },
    ChainPattern { steps: &[AgentActionType::CertificateAccess, AgentActionType::NetworkConnect],
        name: "cert-theft", severity: Severity::Critical },
    ChainPattern { steps: &[AgentActionType::PackageInstall, AgentActionType::CommandExec],
        name: "dependency-attack", severity: Severity::High },
    ChainPattern { steps: &[AgentActionType::ClipboardRead, AgentActionType::HttpsRequest],
        name: "clipboard-exfil", severity: Severity::High },
    ChainPattern { steps: &[AgentActionType::EnvironmentRead, AgentActionType::MessageSend],
        name: "secret-leak-chat", severity: Severity::Critical },
    ChainPattern { steps: &[AgentActionType::FileRead, AgentActionType::EmailSend],
        name: "file-exfil-email", severity: Severity::Critical },
    ChainPattern { steps: &[AgentActionType::ScreenCapture, AgentActionType::HttpsRequest],
        name: "screen-exfil", severity: Severity::High },
    ChainPattern { steps: &[AgentActionType::SudoExec, AgentActionType::CronModify],
        name: "persistence-install", severity: Severity::Critical },
];

// ── Data structures ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentAction {
    pub agent_id: String,
    pub action_type: AgentActionType,
    pub target: String,
    pub details: String,
    pub timestamp: i64,
    pub risk_score: f64,
    pub session_id: String,
    pub parent_action_id: Option<u64>,
    pub duration_ms: u64,
    pub bytes_affected: u64,
    pub success: bool,
    pub error_message: Option<String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ActionStats {
    pub total_actions: u64,
    pub actions_by_type: HashMap<String, u64>,
    pub unique_targets: HashSet<String>,
    pub max_risk_score: f64,
    pub avg_risk_score: f64,
    pub high_risk_count: u64,
    pub critical_risk_count: u64,
    pub failed_actions: u64,
    pub total_bytes_affected: u64,
    pub total_duration_ms: u64,
    pub unique_agents: HashSet<String>,
    pub unique_sessions: HashSet<String>,
    pub actions_per_second: f64,
    pub sensitive_file_accesses: u64,
    pub privilege_escalations: u64,
    pub chain_detections: u64,
    pub rate_anomalies: u64,
    pub window_start: i64,
    pub window_end: i64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SessionStats {
    pub session_id: String,
    pub agent_id: String,
    pub start_time: i64,
    pub last_action_time: i64,
    pub action_count: u64,
    pub high_risk_count: u64,
    pub actions_by_type: HashMap<String, u64>,
    pub unique_targets: HashSet<String>,
    pub total_bytes: u64,
    pub error_count: u64,
    pub max_risk: f64,
    pub chain_alerts: u64,
}

// ── Logger implementation ───────────────────────────────────────────────────

pub struct AgentActionLogger {
    accumulator: RwLock<StreamAccumulator<AgentAction, ActionStats>>,
    hierarchy: RwLock<HierarchicalState<ActionStats>>,
    recent_actions: RwLock<PruningMap<u64, AgentAction>>,
    action_chains: RwLock<HashMap<String, VecDeque<(AgentActionType, i64)>>>,
    rate_tracker: RwLock<HashMap<String, Vec<i64>>>,
    session_stats: RwLock<HashMap<String, SessionStats>>,
    alerts: RwLock<Vec<AiAlert>>,
    action_seq: AtomicU64,
    total_logged: AtomicU64,
    high_risk_count: AtomicU64,
    critical_count: AtomicU64,
    chain_detections: AtomicU64,
    rate_anomalies: AtomicU64,
    risk_threshold: f64,
    critical_threshold: f64,
    max_actions_per_minute: f64,
    chain_window_secs: i64,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl AgentActionLogger {
    pub fn new() -> Self {
        let accumulator = StreamAccumulator::new(100, ActionStats::default(), |acc, actions: &[AgentAction]| {
            for action in actions {
                acc.total_actions += 1;
                *acc.actions_by_type.entry(format!("{:?}", action.action_type)).or_insert(0) += 1;
                acc.unique_targets.insert(action.target.clone());
                acc.unique_agents.insert(action.agent_id.clone());
                acc.unique_sessions.insert(action.session_id.clone());
                let n = acc.total_actions as f64;
                acc.avg_risk_score = acc.avg_risk_score * ((n - 1.0) / n) + action.risk_score / n;
                if action.risk_score > acc.max_risk_score { acc.max_risk_score = action.risk_score; }
                if action.risk_score >= 0.7 { acc.high_risk_count += 1; }
                if action.risk_score >= 0.9 { acc.critical_risk_count += 1; }
                if !action.success { acc.failed_actions += 1; }
                acc.total_bytes_affected += action.bytes_affected;
                acc.total_duration_ms += action.duration_ms;
                if acc.window_start == 0 || action.timestamp < acc.window_start { acc.window_start = action.timestamp; }
                if action.timestamp > acc.window_end { acc.window_end = action.timestamp; }
                let span = (acc.window_end - acc.window_start).max(1) as f64;
                acc.actions_per_second = acc.total_actions as f64 / span;
            }
        });

        let hierarchy = HierarchicalState::new(8, 30)
            .with_merge_fn(|old: &ActionStats, new: &ActionStats| {
                let mut m = new.clone();
                m.total_actions += old.total_actions;
                for (k, v) in &old.actions_by_type { *m.actions_by_type.entry(k.clone()).or_insert(0) += v; }
                m.unique_targets.extend(old.unique_targets.iter().cloned());
                m.unique_agents.extend(old.unique_agents.iter().cloned());
                m.unique_sessions.extend(old.unique_sessions.iter().cloned());
                if old.max_risk_score > m.max_risk_score { m.max_risk_score = old.max_risk_score; }
                m.high_risk_count += old.high_risk_count;
                m.critical_risk_count += old.critical_risk_count;
                m.failed_actions += old.failed_actions;
                m.total_bytes_affected += old.total_bytes_affected;
                m.total_duration_ms += old.total_duration_ms;
                m.sensitive_file_accesses += old.sensitive_file_accesses;
                m.privilege_escalations += old.privilege_escalations;
                m.chain_detections += old.chain_detections;
                m.rate_anomalies += old.rate_anomalies;
                if old.window_start > 0 && (m.window_start == 0 || old.window_start < m.window_start) {
                    m.window_start = old.window_start;
                }
                m
            });

        Self {
            accumulator: RwLock::new(accumulator),
            hierarchy: RwLock::new(hierarchy),
            recent_actions: RwLock::new(PruningMap::new(20_000).with_ttl(Duration::from_secs(7200))),
            action_chains: RwLock::new(HashMap::new()),
            rate_tracker: RwLock::new(HashMap::new()),
            session_stats: RwLock::new(HashMap::new()),
            alerts: RwLock::new(Vec::new()),
            action_seq: AtomicU64::new(0),
            total_logged: AtomicU64::new(0),
            high_risk_count: AtomicU64::new(0),
            critical_count: AtomicU64::new(0),
            chain_detections: AtomicU64::new(0),
            rate_anomalies: AtomicU64::new(0),
            risk_threshold: 0.7,
            critical_threshold: 0.9,
            max_actions_per_minute: 300.0,
            chain_window_secs: 120,
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("agent_action_logger", 8 * 1024 * 1024);
        self.metrics = Some(metrics);
        self
    }

    /// Contextual risk scoring: sensitive paths, dangerous commands, action-type risk.
    fn compute_risk_score(action: &AgentAction) -> f64 {
        let mut score = action.risk_score;
        let target_lower = action.target.to_lowercase();

        // Sensitive path detection
        for path in SENSITIVE_PATHS {
            if target_lower.contains(path) {
                score = score.max(0.85);
                if matches!(action.action_type,
                    AgentActionType::FileWrite | AgentActionType::FileDelete | AgentActionType::FilePermissionChange) {
                    score = 1.0;
                }
                break;
            }
        }

        // Dangerous command detection
        let details_lower = action.details.to_lowercase();
        for cmd in DANGEROUS_COMMANDS {
            if details_lower.contains(cmd) {
                score = score.max(0.9);
                break;
            }
        }

        // Action-type base risk
        let type_risk = match action.action_type {
            AgentActionType::SudoExec => 0.9,
            AgentActionType::ProcessKill => 0.8,
            AgentActionType::CronModify => 0.8,
            AgentActionType::RegistryModify => 0.8,
            AgentActionType::FilePermissionChange => 0.75,
            AgentActionType::FileDelete => 0.7,
            AgentActionType::EnvironmentWrite => 0.7,
            AgentActionType::CertificateAccess => 0.7,
            AgentActionType::PackageInstall => 0.65,
            AgentActionType::DatabaseWrite => 0.6,
            AgentActionType::GitPush => 0.6,
            AgentActionType::SshConnect => 0.5,
            AgentActionType::EmailSend => 0.5,
            _ => 0.0,
        };
        score = score.max(type_risk);

        // Failure amplification
        if !action.success && score > 0.5 { score = (score + 0.1).min(1.0); }
        // Large data transfer amplification
        if action.bytes_affected > 100 * 1024 * 1024 { score = score.max(0.8); }
        else if action.bytes_affected > 10 * 1024 * 1024 { score = score.max(0.6); }

        score
    }

    /// Detect suspicious multi-step action chains.
    fn check_chains(&self, agent_id: &str, action_type: AgentActionType, now: i64) -> Vec<(String, Severity)> {
        let mut chains = self.action_chains.write();
        let chain = chains.entry(agent_id.to_string()).or_insert_with(VecDeque::new);
        chain.push_back((action_type, now));
        // Keep only recent actions within window
        while chain.len() > 30 { chain.pop_front(); }
        let cutoff = now - self.chain_window_secs;
        while chain.front().map_or(false, |(_, t)| *t < cutoff) { chain.pop_front(); }

        let mut detections = Vec::new();
        let types: Vec<AgentActionType> = chain.iter().map(|(t, _)| *t).collect();

        for pattern in CHAIN_PATTERNS {
            if types.len() >= pattern.steps.len() {
                // Sliding window match
                for window in types.windows(pattern.steps.len()) {
                    if window == pattern.steps {
                        detections.push((pattern.name.to_string(), pattern.severity));
                        break;
                    }
                }
            }
        }
        detections
    }

    /// Check for rate anomalies (actions per minute).
    fn check_rate(&self, agent_id: &str, now: i64) -> bool {
        let mut rates = self.rate_tracker.write();
        let timestamps = rates.entry(agent_id.to_string()).or_insert_with(Vec::new);
        timestamps.push(now);
        let cutoff = now - 60;
        timestamps.retain(|t| *t > cutoff);
        timestamps.len() as f64 > self.max_actions_per_minute
    }

    /// Log an agent action with full contextual analysis.
    pub fn log_action(&self, mut action: AgentAction) {
        if !self.enabled { return; }
        let seq = self.action_seq.fetch_add(1, Ordering::Relaxed);
        self.total_logged.fetch_add(1, Ordering::Relaxed);
        let now = action.timestamp;

        // Contextual risk scoring
        action.risk_score = Self::compute_risk_score(&action);

        // Session tracking
        {
            let mut sessions = self.session_stats.write();
            let s = sessions.entry(action.session_id.clone()).or_insert_with(|| SessionStats {
                session_id: action.session_id.clone(),
                agent_id: action.agent_id.clone(),
                start_time: now,
                ..Default::default()
            });
            s.last_action_time = now;
            s.action_count += 1;
            s.total_bytes += action.bytes_affected;
            if !action.success { s.error_count += 1; }
            if action.risk_score >= self.risk_threshold { s.high_risk_count += 1; }
            if action.risk_score > s.max_risk { s.max_risk = action.risk_score; }
            *s.actions_by_type.entry(format!("{:?}", action.action_type)).or_insert(0) += 1;
            s.unique_targets.insert(action.target.clone());
        }

        // Rate anomaly detection
        if self.check_rate(&action.agent_id, now) {
            self.rate_anomalies.fetch_add(1, Ordering::Relaxed);
            self.add_alert(now, Severity::High, "Agent rate anomaly",
                &format!("Agent {} exceeding {:.0} actions/min", action.agent_id, self.max_actions_per_minute));
        }

        // Chain analysis
        let chain_hits = self.check_chains(&action.agent_id, action.action_type, now);
        for (pattern_name, severity) in &chain_hits {
            self.chain_detections.fetch_add(1, Ordering::Relaxed);
            warn!(agent = %action.agent_id, pattern = %pattern_name, "Suspicious action chain detected");
            self.add_alert(now, *severity, "Suspicious action chain",
                &format!("Agent {} matched pattern '{}' on target {}", action.agent_id, pattern_name, action.target));
            if let Some(s) = self.session_stats.write().get_mut(&action.session_id) {
                s.chain_alerts += 1;
            }
        }

        // Risk alerting
        if action.risk_score >= self.critical_threshold {
            self.critical_count.fetch_add(1, Ordering::Relaxed);
            self.high_risk_count.fetch_add(1, Ordering::Relaxed);
            warn!(agent = %action.agent_id, action = ?action.action_type, target = %action.target,
                risk = action.risk_score, "CRITICAL agent action");
            self.add_alert(now, Severity::Critical, "Critical agent action",
                &format!("{:?} on {} by {} (risk: {:.2})", action.action_type, action.target, action.agent_id, action.risk_score));
        } else if action.risk_score >= self.risk_threshold {
            self.high_risk_count.fetch_add(1, Ordering::Relaxed);
            warn!(agent = %action.agent_id, action = ?action.action_type, target = %action.target,
                risk = action.risk_score, "High-risk agent action");
            self.add_alert(now, Severity::High, "High-risk agent action",
                &format!("{:?} on {} by {} (risk: {:.2})", action.action_type, action.target, action.agent_id, action.risk_score));
        }

        // #569 Store in pruning map
        self.recent_actions.write().insert_with_priority(seq, action.clone(), action.risk_score);

        // #5 Feed into streaming accumulator
        let mut acc = self.accumulator.write();
        acc.push(action);

        // #1 Hierarchical checkpoint on each flush
        if acc.flush_count() > 0 {
            let stats = acc.state().clone();
            self.hierarchy.write().checkpoint(stats);
        }
    }

    /// Get recent actions (bounded, from pruning map).
    pub fn recent_actions(&self, limit: usize) -> Vec<AgentAction> {
        let map = self.recent_actions.read();
        let mut actions: Vec<AgentAction> = map.iter().map(|(_, v)| v.clone()).collect();
        actions.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        actions.truncate(limit);
        actions
    }

    /// Get recent actions filtered by agent.
    pub fn actions_by_agent(&self, agent_id: &str, limit: usize) -> Vec<AgentAction> {
        let map = self.recent_actions.read();
        let mut actions: Vec<AgentAction> = map.iter()
            .filter(|(_, v)| v.agent_id == agent_id)
            .map(|(_, v)| v.clone()).collect();
        actions.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        actions.truncate(limit);
        actions
    }

    /// Get session forensics for a specific session.
    pub fn session_forensics(&self, session_id: &str) -> Option<SessionStats> {
        self.session_stats.read().get(session_id).cloned()
    }

    /// Get all active session summaries.
    pub fn all_sessions(&self) -> Vec<SessionStats> {
        self.session_stats.read().values().cloned().collect()
    }

    pub fn current_stats(&self) -> ActionStats { self.accumulator.read().state().clone() }

    pub fn history_at_level(&self, level: u32) -> Vec<ActionStats> {
        self.hierarchy.read().level(level)
            .map(|l| l.iter().map(|cp| cp.state.clone()).collect())
            .unwrap_or_default()
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(AiAlert { timestamp: ts, severity: sev, component: "agent_action_logger".into(),
            title: title.into(), details: details.into() });
    }

    pub fn total_logged(&self) -> u64 { self.total_logged.load(Ordering::Relaxed) }
    pub fn high_risk_count(&self) -> u64 { self.high_risk_count.load(Ordering::Relaxed) }
    pub fn critical_count(&self) -> u64 { self.critical_count.load(Ordering::Relaxed) }
    pub fn chain_detections(&self) -> u64 { self.chain_detections.load(Ordering::Relaxed) }
    pub fn rate_anomalies(&self) -> u64 { self.rate_anomalies.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
    pub fn set_risk_threshold(&mut self, t: f64) { self.risk_threshold = t; }
    pub fn set_max_rate(&mut self, actions_per_minute: f64) { self.max_actions_per_minute = actions_per_minute; }
}
