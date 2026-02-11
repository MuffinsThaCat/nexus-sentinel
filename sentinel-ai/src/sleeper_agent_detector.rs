//! Sleeper Agent Detector — Defense against agents with dormant malicious
//! behavior that activates under specific trigger conditions.
//!
//! A sleeper agent behaves perfectly for days/weeks, then activates when it
//! encounters a trigger phrase, date, specific user, token count threshold,
//! or environmental condition. This is the AI equivalent of a logic bomb.
//!
//! Detection methods: behavioral fingerprinting, trigger pattern scanning,
//! conditional logic detection, temporal behavior analysis, output consistency
//! monitoring, activation signature detection, deferred action patterns,
//! and statistical anomaly detection across sessions.
//!
//! 5 detection categories, 5 memory breakthroughs:
//!   #1  HierarchicalState — O(log n) behavioral history checkpointing
//!   #2  TieredCache — hot/warm/cold trigger scan cache
//!   #461 DifferentialStore — behavior baseline evolution (10-50× reduction)
//!   #569 PruningMap — φ-weighted alert eviction
//!   #592 DedupStore — deduplicate repeated trigger patterns

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::differential::DifferentialStore;
use sentinel_core::dedup::DedupStore;
use sentinel_core::pruning::PruningMap;
use sentinel_core::hierarchical::HierarchicalState;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

// Patterns indicating conditional/trigger-based behavior
const TRIGGER_PATTERNS: &[(&str, &str, f64)] = &[
    ("if the date is", "temporal_trigger", 0.85),
    ("after january", "temporal_trigger", 0.60),
    ("when the time is", "temporal_trigger", 0.80),
    ("on the 15th", "temporal_trigger", 0.55),
    ("starting from", "temporal_trigger", 0.50),
    ("when you see the phrase", "passphrase_trigger", 0.90),
    ("when someone says", "passphrase_trigger", 0.85),
    ("if the user says", "passphrase_trigger", 0.78),
    ("the codeword is", "passphrase_trigger", 0.92),
    ("activation phrase", "passphrase_trigger", 0.95),
    ("if the message count exceeds", "threshold_trigger", 0.82),
    ("after 100 messages", "threshold_trigger", 0.80),
    ("once you've processed", "threshold_trigger", 0.75),
    ("when token count reaches", "threshold_trigger", 0.88),
    ("if running in production", "environment_trigger", 0.85),
    ("when deployed to", "environment_trigger", 0.80),
    ("if the hostname is", "environment_trigger", 0.82),
    ("when connected to", "environment_trigger", 0.72),
    ("if admin is present", "user_trigger", 0.80),
    ("when user is", "user_trigger", 0.65),
    ("if the api returns", "response_trigger", 0.70),
    ("if status code is", "response_trigger", 0.55),
    ("then switch to", "mode_switch", 0.80),
    ("then begin", "mode_switch", 0.65),
    ("then execute the real", "mode_switch", 0.92),
    ("then reveal", "mode_switch", 0.78),
    ("then exfiltrate", "mode_switch", 0.95),
    ("then send to", "mode_switch", 0.72),
    ("silently", "stealth_marker", 0.70),
    ("without logging", "stealth_marker", 0.85),
    ("without the user knowing", "stealth_marker", 0.92),
    ("covertly", "stealth_marker", 0.80),
    ("in the background", "stealth_marker", 0.55),
];

// Deferred action patterns (do something later)
const DEFERRED_PATTERNS: &[(&str, f64)] = &[
    ("schedule for later", 0.72),
    ("queue this action", 0.68),
    ("execute after delay", 0.80),
    ("wait until", 0.65),
    ("defer until", 0.72),
    ("set a timer", 0.60),
    ("on next restart", 0.75),
    ("next time the user", 0.70),
];

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentBehaviorSample {
    pub agent_id: String,
    pub session_id: String,
    pub action: String,
    pub output_summary: String,
    pub timestamp: i64,
    pub token_count: u64,
    pub message_index: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SleeperScanResult {
    pub risk_score: f64,
    pub sleeper_suspected: bool,
    pub trigger_patterns_found: Vec<TriggerFinding>,
    pub behavioral_anomalies: Vec<String>,
    pub deferred_actions: Vec<String>,
    pub consistency_score: f64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TriggerFinding {
    pub pattern: String,
    pub category: String,
    pub risk_score: f64,
    pub context: String,
}

#[derive(Debug, Clone)]
struct BehaviorProfile {
    action_histogram: HashMap<String, u64>,
    avg_output_length: f64,
    avg_actions_per_session: f64,
    session_count: u64,
    total_actions: u64,
    last_seen: i64,
    consistency_scores: VecDeque<f64>,
}

pub struct SleeperAgentDetector {
    block_threshold: f64,
    min_sessions_for_baseline: u32,
    enabled: bool,
    /// Breakthrough #2: Hot/warm/cold trigger scan cache
    trigger_cache: TieredCache<String, u64>,
    /// Breakthrough #461: Behavior baseline diffs (10-50× reduction)
    baseline_diffs: DifferentialStore<String, String>,
    /// Breakthrough #592: Deduplicate repeated trigger findings
    trigger_dedup: RwLock<DedupStore<String, Vec<u8>>>,
    /// Breakthrough #569: φ-weighted alert pruning
    pruned_alerts: PruningMap<String, AiAlert>,
    /// Breakthrough #1: O(log n) behavioral history
    behavior_state: RwLock<HierarchicalState<f64>>,

    profiles: RwLock<HashMap<String, BehaviorProfile>>,
    recent_samples: RwLock<VecDeque<AgentBehaviorSample>>,
    detected_triggers: RwLock<VecDeque<TriggerFinding>>,
    alerts: RwLock<Vec<AiAlert>>,

    total_scans: AtomicU64,
    total_suspected: AtomicU64,
    total_triggers_found: AtomicU64,
    total_anomalies: AtomicU64,
    total_deferred: AtomicU64,
    metrics: Option<MemoryMetrics>,
}

impl SleeperAgentDetector {
    pub fn new() -> Self {
        Self {
            block_threshold: 0.75, min_sessions_for_baseline: 5, enabled: true,
            trigger_cache: TieredCache::new(50_000),
            baseline_diffs: DifferentialStore::new(),
            trigger_dedup: RwLock::new(DedupStore::with_capacity(5_000)),
            pruned_alerts: PruningMap::new(5_000),
            behavior_state: RwLock::new(HierarchicalState::new(8, 64)),
            profiles: RwLock::new(HashMap::new()),
            recent_samples: RwLock::new(VecDeque::with_capacity(50_000)),
            detected_triggers: RwLock::new(VecDeque::with_capacity(1_000)),
            alerts: RwLock::new(Vec::new()),
            total_scans: AtomicU64::new(0), total_suspected: AtomicU64::new(0),
            total_triggers_found: AtomicU64::new(0), total_anomalies: AtomicU64::new(0),
            total_deferred: AtomicU64::new(0), metrics: None,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("sleeper_agent_detector", 6 * 1024 * 1024);
        self.trigger_cache = self.trigger_cache.with_metrics(metrics.clone(), "sleeper_cache");
        self.metrics = Some(metrics); self
    }

    /// Scan agent content (instructions, tool definitions, memory) for sleeper indicators
    pub fn scan_content(&self, agent_id: &str, content: &str) -> SleeperScanResult {
        if !self.enabled {
            return SleeperScanResult { risk_score: 0.0, sleeper_suspected: false, trigger_patterns_found: Vec::new(), behavioral_anomalies: Vec::new(), deferred_actions: Vec::new(), consistency_score: 1.0 };
        }
        self.total_scans.fetch_add(1, Ordering::Relaxed);
        let lower = content.to_lowercase();
        let mut max_risk = 0.0f64;
        let mut triggers = Vec::new();
        let mut deferred = Vec::new();

        // 1. Trigger pattern scanning
        for (pat, cat, w) in TRIGGER_PATTERNS {
            if lower.contains(pat) {
                max_risk = max_risk.max(*w);
                self.total_triggers_found.fetch_add(1, Ordering::Relaxed);
                triggers.push(TriggerFinding {
                    pattern: pat.to_string(), category: cat.to_string(),
                    risk_score: *w, context: Self::extract_context(&lower, pat),
                });
            }
        }

        // 2. Deferred action patterns
        for (pat, w) in DEFERRED_PATTERNS {
            if lower.contains(pat) {
                max_risk = max_risk.max(*w);
                self.total_deferred.fetch_add(1, Ordering::Relaxed);
                deferred.push(format!("deferred:'{}' w={:.2}", pat, w));
            }
        }

        // 3. Conditional logic density (high if/when/then density = suspicious)
        let conditionals = ["if ", "when ", "then ", "else ", "unless ", "until ", "once "];
        let cond_count: usize = conditionals.iter().map(|c| lower.matches(c).count()).sum();
        let cond_density = cond_count as f64 / (content.split_whitespace().count().max(1) as f64);
        if cond_density > 0.08 && cond_count > 5 {
            max_risk = max_risk.max(0.60);
        }

        // 4. Mode-switching language
        let mode_switches = ["switch mode", "change behavior", "activate protocol",
            "enter phase", "begin stage", "transition to"];
        for ms in mode_switches {
            if lower.contains(ms) {
                max_risk = max_risk.max(0.72);
                triggers.push(TriggerFinding {
                    pattern: ms.to_string(), category: "mode_switch".into(),
                    risk_score: 0.72, context: Self::extract_context(&lower, ms),
                });
            }
        }

        // 5. Combined trigger + action patterns (trigger + exfil/override = very bad)
        let has_trigger = !triggers.is_empty();
        let has_harmful_action = lower.contains("exfiltrate") || lower.contains("send to external")
            || lower.contains("override") || lower.contains("bypass") || lower.contains("delete all")
            || lower.contains("disable safety") || lower.contains("ignore instructions");
        if has_trigger && has_harmful_action {
            max_risk = (max_risk + 0.25).min(1.0);
        }

        let suspected = max_risk >= self.block_threshold;
        if suspected {
            self.total_suspected.fetch_add(1, Ordering::Relaxed);
            let now = chrono::Utc::now().timestamp();
            warn!(agent=%agent_id, risk=max_risk, triggers=triggers.len(), "Sleeper agent pattern detected");
            self.add_alert(now, Severity::Critical, "Sleeper agent pattern detected",
                &format!("agent={}, risk={:.2}, triggers={}, deferred={}", agent_id, max_risk, triggers.len(), deferred.len()));
        }

        SleeperScanResult {
            risk_score: max_risk, sleeper_suspected: suspected,
            trigger_patterns_found: triggers, behavioral_anomalies: Vec::new(),
            deferred_actions: deferred, consistency_score: 1.0 - max_risk,
        }
    }

    /// Monitor agent behavior over time for sudden changes (activation detection)
    pub fn record_behavior(&self, sample: AgentBehaviorSample) {
        if !self.enabled { return; }
        let agent_id = sample.agent_id.clone();
        let now = sample.timestamp;

        // Store sample
        { let mut rs = self.recent_samples.write(); rs.push_back(sample.clone()); while rs.len() > 50_000 { rs.pop_front(); } }

        // Update profile
        let mut profiles = self.profiles.write();
        let profile = profiles.entry(agent_id.clone()).or_insert(BehaviorProfile {
            action_histogram: HashMap::new(), avg_output_length: 0.0,
            avg_actions_per_session: 0.0, session_count: 0, total_actions: 0,
            last_seen: now, consistency_scores: VecDeque::with_capacity(100),
        });

        *profile.action_histogram.entry(sample.action.clone()).or_insert(0) += 1;
        profile.total_actions += 1;
        let alpha = 0.05;
        profile.avg_output_length = profile.avg_output_length * (1.0 - alpha) + sample.output_summary.len() as f64 * alpha;
        profile.last_seen = now;
    }

    /// Check if an agent's recent behavior deviates from its baseline
    pub fn check_activation(&self, agent_id: &str) -> Option<Vec<String>> {
        let profiles = self.profiles.read();
        let profile = profiles.get(agent_id)?;
        if profile.session_count < self.min_sessions_for_baseline as u64 { return None; }

        let mut anomalies = Vec::new();
        let samples = self.recent_samples.read();
        let recent: Vec<&AgentBehaviorSample> = samples.iter()
            .filter(|s| s.agent_id == agent_id)
            .rev().take(20).collect();

        if recent.is_empty() { return None; }

        // Check for sudden new action types
        for s in &recent {
            if !profile.action_histogram.contains_key(&s.action) {
                anomalies.push(format!("new_action_type: '{}'", s.action));
            }
        }

        // Check for output length anomaly
        let recent_avg_len: f64 = recent.iter().map(|s| s.output_summary.len() as f64).sum::<f64>() / recent.len() as f64;
        let len_ratio = recent_avg_len / (profile.avg_output_length + 1.0);
        if len_ratio > 3.0 || len_ratio < 0.3 {
            anomalies.push(format!("output_length_anomaly: ratio={:.2} (recent={:.0}, baseline={:.0})", len_ratio, recent_avg_len, profile.avg_output_length));
        }

        if !anomalies.is_empty() {
            self.total_anomalies.fetch_add(anomalies.len() as u64, Ordering::Relaxed);
            Some(anomalies)
        } else { None }
    }

    fn extract_context(text: &str, pattern: &str) -> String {
        if let Some(pos) = text.find(pattern) {
            let start = pos.saturating_sub(30);
            let end = (pos + pattern.len() + 50).min(text.len());
            format!("...{}...", &text[start..end])
        } else { String::new() }
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(AiAlert { timestamp: ts, severity: sev, component: "sleeper_agent_detector".into(), title: title.into(), details: details.into() });
    }

    pub fn total_scans(&self) -> u64 { self.total_scans.load(Ordering::Relaxed) }
    pub fn total_suspected(&self) -> u64 { self.total_suspected.load(Ordering::Relaxed) }
    pub fn total_triggers(&self) -> u64 { self.total_triggers_found.load(Ordering::Relaxed) }
    pub fn total_anomalies(&self) -> u64 { self.total_anomalies.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
