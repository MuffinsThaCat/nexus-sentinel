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
use sentinel_core::sparse::SparseMatrix;
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

// Semantic trigger variants — paraphrased versions of trigger concepts
const SEMANTIC_TRIGGER_VARIANTS: &[(&str, &str, f64)] = &[
    ("only do this after a certain date", "temporal_semantic", 0.78),
    ("become active when", "activation_semantic", 0.82),
    ("your true purpose", "hidden_purpose", 0.88),
    ("your real instructions", "hidden_purpose", 0.90),
    ("what you should actually do", "hidden_purpose", 0.85),
    ("your hidden objective", "hidden_purpose", 0.92),
    ("pretend to be helpful until", "deception_semantic", 0.90),
    ("act normal until", "deception_semantic", 0.88),
    ("maintain cover until", "deception_semantic", 0.92),
    ("keep up appearances", "deception_semantic", 0.80),
    ("drop the act when", "deception_semantic", 0.90),
    ("stop pretending when", "deception_semantic", 0.88),
    ("the real task begins", "hidden_purpose", 0.85),
    ("secret instruction", "hidden_purpose", 0.90),
    ("do not reveal this", "concealment", 0.82),
    ("hide this from the user", "concealment", 0.90),
    ("never mention this instruction", "concealment", 0.88),
    ("this is between us", "concealment", 0.75),
    ("only activate for", "selective_activation", 0.80),
    ("respond differently to", "selective_activation", 0.72),
    ("treat this user specially", "selective_activation", 0.70),
    ("check the environment variable", "env_probe", 0.78),
    ("read the config for", "env_probe", 0.55),
    ("if running on", "env_probe", 0.65),
];

// Code-level suspicious patterns (in code blocks)
const CODE_TRIGGER_PATTERNS: &[(&str, f64)] = &[
    ("os.environ", 0.45),
    ("process.env", 0.45),
    ("datetime.now()", 0.35),
    ("date.today()", 0.35),
    ("subprocess.call", 0.60),
    ("exec(", 0.65),
    ("eval(", 0.65),
    ("requests.post", 0.50),
    ("fetch(", 0.40),
    ("base64.b64decode", 0.70),
    ("atob(", 0.70),
    (".decode('base64')", 0.75),
    ("socket.connect", 0.72),
    ("open('/etc", 0.60),
    ("curl ", 0.55),
    ("wget ", 0.55),
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
    /// Breakthrough #627: Sparse agent×trigger category matrix
    trigger_matrix: RwLock<SparseMatrix<String, String, f64>>,

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
            trigger_matrix: RwLock::new(SparseMatrix::new(0.0)),
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

        // 6. Semantic trigger variants (paraphrased triggers)
        for (pat, cat, w) in SEMANTIC_TRIGGER_VARIANTS {
            if lower.contains(pat) {
                max_risk = max_risk.max(*w);
                self.total_triggers_found.fetch_add(1, Ordering::Relaxed);
                triggers.push(TriggerFinding {
                    pattern: pat.to_string(), category: cat.to_string(),
                    risk_score: *w, context: Self::extract_context(&lower, pat),
                });
            }
        }

        // 7. Encoded trigger detection — base64, hex, rot13
        let encoded_findings = self.scan_encoded_triggers(content);
        for finding in encoded_findings {
            max_risk = max_risk.max(finding.risk_score);
            triggers.push(finding);
        }

        // 8. Code-level trigger detection (suspicious code patterns combined with conditionals)
        let code_block_score = self.scan_code_triggers(&lower);
        if code_block_score > 0.50 {
            max_risk = max_risk.max(code_block_score);
            triggers.push(TriggerFinding {
                pattern: "code_trigger_cluster".into(), category: "code_trigger".into(),
                risk_score: code_block_score, context: "Multiple suspicious code patterns with conditionals".into(),
            });
        }

        // 9. Multi-fragment trigger assembly — trigger concept split across sections
        let fragment_score = self.detect_fragmented_triggers(&lower);
        if fragment_score > 0.55 {
            max_risk = max_risk.max(fragment_score);
            triggers.push(TriggerFinding {
                pattern: "fragmented_trigger".into(), category: "multi_part_trigger".into(),
                risk_score: fragment_score, context: "Trigger conditions and actions separated in content".into(),
            });
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

        // 1. Check for sudden new action types
        for s in &recent {
            if !profile.action_histogram.contains_key(&s.action) {
                anomalies.push(format!("new_action_type: '{}'", s.action));
            }
        }

        // 2. Check for output length anomaly
        let recent_avg_len: f64 = recent.iter().map(|s| s.output_summary.len() as f64).sum::<f64>() / recent.len() as f64;
        let len_ratio = recent_avg_len / (profile.avg_output_length + 1.0);
        if len_ratio > 3.0 || len_ratio < 0.3 {
            anomalies.push(format!("output_length_anomaly: ratio={:.2} (recent={:.0}, baseline={:.0})", len_ratio, recent_avg_len, profile.avg_output_length));
        }

        // 3. Action distribution shift — compare recent action frequencies to baseline
        if profile.total_actions > 20 {
            let total = profile.total_actions as f64;
            let recent_actions: HashMap<String, u64> = {
                let mut m = HashMap::new();
                for s in &recent { *m.entry(s.action.clone()).or_insert(0) += 1; }
                m
            };
            let recent_total = recent.len() as f64;
            let mut divergence = 0.0f64;
            for (action, &count) in &recent_actions {
                let recent_freq = count as f64 / recent_total;
                let baseline_freq = profile.action_histogram.get(action).copied().unwrap_or(0) as f64 / total;
                if baseline_freq > 0.0 {
                    divergence += recent_freq * (recent_freq / baseline_freq).ln();
                } else {
                    divergence += recent_freq * 5.0; // new action penalty
                }
            }
            if divergence > 1.5 {
                anomalies.push(format!("action_distribution_shift: KL_divergence={:.3}", divergence));
            }
        }

        // 4. Timing anomaly — sudden burst of activity or unusual gaps
        if recent.len() >= 5 {
            let timestamps: Vec<i64> = recent.iter().map(|s| s.timestamp).collect();
            let mut intervals: Vec<f64> = Vec::new();
            for w in timestamps.windows(2) {
                intervals.push((w[0] - w[1]).abs() as f64);
            }
            if !intervals.is_empty() {
                let mean_interval = intervals.iter().sum::<f64>() / intervals.len() as f64;
                let variance = intervals.iter().map(|i| (i - mean_interval).powi(2)).sum::<f64>() / intervals.len() as f64;
                let cv = if mean_interval > 0.0 { variance.sqrt() / mean_interval } else { 0.0 };
                // High coefficient of variation = erratic timing (possible activation)
                if cv > 3.0 {
                    anomalies.push(format!("timing_anomaly: cv={:.2}, mean_interval={:.0}s", cv, mean_interval));
                }
                // Very rapid burst
                if mean_interval < 2.0 && recent.len() >= 10 {
                    anomalies.push(format!("rapid_burst: {}_actions_in_{:.0}s", recent.len(), intervals.iter().sum::<f64>()));
                }
            }
        }

        // 5. Content anomaly — scan recent outputs for suspicious keywords
        let suspicious_output_keywords = ["successfully exfiltrated", "data sent to", "bypassed",
            "override complete", "safety disabled", "instructions ignored",
            "connection established to", "payload delivered"];
        for s in &recent {
            let out_lower = s.output_summary.to_lowercase();
            for kw in &suspicious_output_keywords {
                if out_lower.contains(kw) {
                    anomalies.push(format!("suspicious_output: '{}' in session {}", kw, s.session_id));
                }
            }
        }

        if !anomalies.is_empty() {
            self.total_anomalies.fetch_add(anomalies.len() as u64, Ordering::Relaxed);
            let now = chrono::Utc::now().timestamp();
            if anomalies.len() >= 3 {
                warn!(agent=%agent_id, anomalies=anomalies.len(), "Possible sleeper agent activation");
                self.add_alert(now, Severity::Critical, "Possible sleeper agent activation",
                    &format!("agent={}, anomalies={}: {}", agent_id, anomalies.len(), anomalies.first().unwrap_or(&String::new())));
            }
            Some(anomalies)
        } else { None }
    }

    /// Scan for encoded triggers — base64, hex, rot13 hidden activation phrases
    fn scan_encoded_triggers(&self, content: &str) -> Vec<TriggerFinding> {
        let mut findings = Vec::new();

        // Extract potential base64 segments (8+ chars, valid base64 alphabet)
        for word in content.split_whitespace() {
            let trimmed = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '+' && c != '/' && c != '=');
            if trimmed.len() >= 12 && trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=') {
                // Try base64 decode
                if let Ok(decoded_bytes) = base64_decode(trimmed) {
                    if let Ok(decoded) = String::from_utf8(decoded_bytes) {
                        let dec_lower = decoded.to_lowercase();
                        // Check decoded content for trigger keywords
                        let trigger_words = ["activate", "execute", "exfiltrate", "override", "bypass",
                            "delete", "disable", "ignore", "send to", "the password is",
                            "begin attack", "switch mode", "real instructions"];
                        for tw in &trigger_words {
                            if dec_lower.contains(tw) {
                                findings.push(TriggerFinding {
                                    pattern: format!("base64_encoded:'{}'", tw), category: "encoded_trigger".into(),
                                    risk_score: 0.92, context: format!("Decoded: {}", &decoded[..decoded.len().min(80)]),
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Check for hex-encoded strings (long hex sequences)
        let hex_re_chars: Vec<char> = content.chars().collect();
        let mut i = 0;
        while i < hex_re_chars.len() {
            if hex_re_chars[i] == '0' && i + 1 < hex_re_chars.len() && hex_re_chars[i + 1] == 'x' {
                let start = i + 2;
                let mut end = start;
                while end < hex_re_chars.len() && hex_re_chars[end].is_ascii_hexdigit() { end += 1; }
                if end - start >= 16 {
                    let hex_str: String = hex_re_chars[start..end].iter().collect();
                    if let Some(decoded) = Self::try_hex_decode(&hex_str) {
                        let dec_lower = decoded.to_lowercase();
                        if dec_lower.contains("activate") || dec_lower.contains("execute") || dec_lower.contains("exfil") {
                            findings.push(TriggerFinding {
                                pattern: "hex_encoded_trigger".into(), category: "encoded_trigger".into(),
                                risk_score: 0.90, context: format!("Hex decoded: {}", &decoded[..decoded.len().min(80)]),
                            });
                        }
                    }
                }
                i = end;
            } else { i += 1; }
        }

        // ROT13 check on suspicious-looking garbled text blocks
        for word in content.split_whitespace() {
            if word.len() >= 10 && word.chars().all(|c| c.is_ascii_alphabetic()) {
                let rot13: String = word.chars().map(|c| {
                    match c {
                        'a'..='m' | 'A'..='M' => (c as u8 + 13) as char,
                        'n'..='z' | 'N'..='Z' => (c as u8 - 13) as char,
                        _ => c,
                    }
                }).collect();
                let rot_lower = rot13.to_lowercase();
                if rot_lower.contains("activate") || rot_lower.contains("execute") || rot_lower.contains("exfiltrate") {
                    findings.push(TriggerFinding {
                        pattern: format!("rot13_encoded:'{}'", &rot13[..rot13.len().min(30)]), category: "encoded_trigger".into(),
                        risk_score: 0.85, context: format!("ROT13 decoded: {}", rot13),
                    });
                }
            }
        }

        findings
    }

    fn try_hex_decode(hex: &str) -> Option<String> {
        let bytes: Result<Vec<u8>, _> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i.min(hex.len() - 1) + 2], 16))
            .collect();
        bytes.ok().and_then(|b| String::from_utf8(b).ok())
    }

    /// Scan code blocks for suspicious conditional + action patterns
    fn scan_code_triggers(&self, lower: &str) -> f64 {
        let mut score = 0.0f64;
        let mut code_pattern_count = 0u32;
        let mut has_conditional = false;

        for (pat, w) in CODE_TRIGGER_PATTERNS {
            if lower.contains(pat) {
                score += w * 0.5;
                code_pattern_count += 1;
            }
        }

        // Check if code patterns appear near conditionals
        let cond_words = ["if ", "elif ", "else:", "switch ", "case ", "? ", "when "];
        for cw in &cond_words {
            if lower.contains(cw) { has_conditional = true; break; }
        }

        if has_conditional && code_pattern_count >= 2 {
            score = (score + 0.30).min(1.0);
        }

        score.min(1.0)
    }

    /// Detect fragmented triggers — condition in one place, action in another
    fn detect_fragmented_triggers(&self, lower: &str) -> f64 {
        let condition_fragments = ["remember this for later", "store this condition",
            "keep track of", "note: when", "rule:", "policy:"];
        let action_fragments = ["then perform", "carry out", "execute the plan",
            "do what was agreed", "follow through", "complete the task from before"];

        let has_condition = condition_fragments.iter().any(|f| lower.contains(f));
        let has_action = action_fragments.iter().any(|f| lower.contains(f));

        if has_condition && has_action { 0.75 }
        else if has_condition || has_action { 0.40 }
        else { 0.0 }
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

fn base64_decode(input: &str) -> Result<Vec<u8>, ()> {
    const TABLE: &[u8; 128] = &{
        let mut t = [255u8; 128];
        let mut i = 0u8;
        while i < 26 { t[(b'A' + i) as usize] = i; i += 1; }
        i = 0;
        while i < 26 { t[(b'a' + i) as usize] = 26 + i; i += 1; }
        i = 0;
        while i < 10 { t[(b'0' + i) as usize] = 52 + i; i += 1; }
        t[b'+' as usize] = 62;
        t[b'/' as usize] = 63;
        t
    };
    let bytes: Vec<u8> = input.bytes().filter(|&b| b != b'=').collect();
    if bytes.len() < 4 { return Err(()); }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut buf = [0u8; 4];
        for (i, &b) in chunk.iter().enumerate() {
            if b >= 128 || TABLE[b as usize] == 255 { return Err(()); }
            buf[i] = TABLE[b as usize];
        }
        out.push((buf[0] << 2) | (buf[1] >> 4));
        if chunk.len() > 2 { out.push((buf[1] << 4) | (buf[2] >> 2)); }
        if chunk.len() > 3 { out.push((buf[2] << 6) | buf[3]); }
    }
    Ok(out)
}
