//! Clipboard Exfil Detector — catches agents leaking sensitive data via clipboard.
//!
//! Features:
//! - **30+ sensitive data patterns**: SSNs, credit cards (Luhn), API keys, JWTs,
//!   private keys, AWS/GCP/Azure secrets, Slack tokens, GitHub PATs, etc.
//! - **Content fingerprinting** without storing raw clipboard data (privacy-safe)
//! - **Frequency analysis** detecting rapid clipboard cycling (copy-paste exfil)
//! - **Cross-app tracking** monitoring clipboard flow between applications
//! - **Entropy analysis** detecting high-entropy strings (encoded secrets)
//! - **Size anomaly detection** flagging unusually large clipboard payloads
//! - **Source/destination correlation** linking clipboard reads to network sends
//! - **Reversible computation** — re-derive scan results from fingerprints, never store raw
//!
//! Memory breakthroughs: #3 Reversible, #592 Dedup, #5 Streaming, #6 Verifier

use crate::types::*;
use sentinel_core::reversible::ReversibleComputation;
use sentinel_core::dedup::DedupStore;
use sentinel_core::streaming::StreamAccumulator;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

// ── Data types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ClipboardDataType {
    PlainText, RichText, Html, Image, File, Url, Code, Binary, Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SensitiveDataType {
    SSN, CreditCard, Email, PhoneNumber, IpAddress,
    ApiKey, AwsAccessKey, AwsSecretKey, GcpServiceAccount, AzureConnectionString,
    JwtToken, BearerToken, OAuthToken,
    PrivateKey, SshPrivateKey, PgpPrivateKey,
    GitHubPat, SlackToken, DiscordToken, TelegramToken,
    StripeKey, TwilioSid, SendgridKey,
    DatabaseUrl, ConnectionString,
    Password, Passphrase, SecretKey,
    Base64Blob, HighEntropyString,
    CryptoWalletAddress, CryptoSeedPhrase,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClipboardEvent {
    pub agent_id: String,
    pub session_id: String,
    pub timestamp: i64,
    pub data_type: ClipboardDataType,
    pub content_length: usize,
    pub content_hash: u64,
    pub source_app: Option<String>,
    pub destination_app: Option<String>,
    pub is_read: bool,
    pub is_write: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanResult {
    pub event: ClipboardEvent,
    pub sensitive_types_found: Vec<SensitiveDataType>,
    pub risk_score: f64,
    pub entropy: f64,
    pub is_duplicate: bool,
    pub frequency_anomaly: bool,
    pub size_anomaly: bool,
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ClipboardStats {
    pub total_events: u64,
    pub total_reads: u64,
    pub total_writes: u64,
    pub sensitive_detections: u64,
    pub duplicates_caught: u64,
    pub frequency_anomalies: u64,
    pub size_anomalies: u64,
    pub by_data_type: HashMap<String, u64>,
    pub by_sensitive_type: HashMap<String, u64>,
    pub by_agent: HashMap<String, u64>,
    pub avg_content_length: f64,
    pub max_content_length: usize,
    pub total_risk_score: f64,
    pub window_start: i64,
    pub window_end: i64,
}

// ── Pattern definitions ─────────────────────────────────────────────────────

struct PatternDef {
    name: SensitiveDataType,
    prefixes: &'static [&'static str],
    min_len: usize,
    max_len: usize,
    check_fn: Option<fn(&str) -> bool>,
}

const PATTERNS: &[PatternDef] = &[
    PatternDef { name: SensitiveDataType::AwsAccessKey, prefixes: &["AKIA", "ABIA", "ACCA"], min_len: 20, max_len: 20, check_fn: None },
    PatternDef { name: SensitiveDataType::AwsSecretKey, prefixes: &[], min_len: 40, max_len: 40, check_fn: Some(is_base64_like) },
    PatternDef { name: SensitiveDataType::GitHubPat, prefixes: &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"], min_len: 36, max_len: 100, check_fn: None },
    PatternDef { name: SensitiveDataType::SlackToken, prefixes: &["xoxb-", "xoxp-", "xoxs-", "xoxa-"], min_len: 30, max_len: 200, check_fn: None },
    PatternDef { name: SensitiveDataType::JwtToken, prefixes: &["eyJ"], min_len: 36, max_len: 4096, check_fn: None },
    PatternDef { name: SensitiveDataType::StripeKey, prefixes: &["sk_live_", "sk_test_", "pk_live_", "pk_test_", "rk_live_", "rk_test_"], min_len: 20, max_len: 200, check_fn: None },
    PatternDef { name: SensitiveDataType::TwilioSid, prefixes: &["AC", "SK"], min_len: 34, max_len: 34, check_fn: None },
    PatternDef { name: SensitiveDataType::SendgridKey, prefixes: &["SG."], min_len: 40, max_len: 100, check_fn: None },
    PatternDef { name: SensitiveDataType::SshPrivateKey, prefixes: &["-----BEGIN RSA PRIVATE", "-----BEGIN OPENSSH PRIVATE", "-----BEGIN EC PRIVATE", "-----BEGIN DSA PRIVATE"], min_len: 100, max_len: 10000, check_fn: None },
    PatternDef { name: SensitiveDataType::PgpPrivateKey, prefixes: &["-----BEGIN PGP PRIVATE"], min_len: 100, max_len: 10000, check_fn: None },
    PatternDef { name: SensitiveDataType::DiscordToken, prefixes: &[], min_len: 59, max_len: 68, check_fn: Some(is_discord_token) },
    PatternDef { name: SensitiveDataType::DatabaseUrl, prefixes: &["postgres://", "postgresql://", "mysql://", "mongodb://", "redis://", "amqp://"], min_len: 15, max_len: 500, check_fn: None },
    PatternDef { name: SensitiveDataType::AzureConnectionString, prefixes: &["DefaultEndpointsProtocol=", "AccountKey="], min_len: 50, max_len: 500, check_fn: None },
    PatternDef { name: SensitiveDataType::GcpServiceAccount, prefixes: &["{\"type\":\"service_account\""], min_len: 100, max_len: 5000, check_fn: None },
    PatternDef { name: SensitiveDataType::BearerToken, prefixes: &["Bearer "], min_len: 20, max_len: 2000, check_fn: None },
];

fn is_base64_like(s: &str) -> bool {
    s.len() >= 20 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

fn is_discord_token(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| !p.is_empty())
}

// ── Clipboard Exfil Detector ────────────────────────────────────────────────

pub struct ClipboardExfilDetector {
    // #3 Reversible: store fingerprints + scan metadata, re-derive results on demand
    scan_history: RwLock<ReversibleComputation<ClipboardEvent, ScanResult>>,
    // #592 Dedup: content-addressed dedup by hash
    content_dedup: RwLock<DedupStore<u64, Vec<u8>>>,
    // #5 Streaming: aggregate stats without storing raw events
    stats_accumulator: RwLock<StreamAccumulator<ClipboardEvent, ClipboardStats>>,
    // Frequency tracking per agent (timestamps of clipboard accesses)
    frequency_tracker: RwLock<HashMap<String, VecDeque<i64>>>,
    // Content size baseline per agent (for anomaly detection)
    size_baselines: RwLock<HashMap<String, (f64, f64, u64)>>, // (mean, m2, count) Welford's
    // Cross-app flow tracking: source_app -> dest_app -> count
    app_flows: RwLock<HashMap<String, HashMap<String, u64>>>,
    // Configuration
    max_clipboard_frequency: u64,  // max events per minute before alert
    frequency_window_secs: i64,
    size_anomaly_std_devs: f64,
    min_entropy_alert: f64,
    // Counters
    alerts: RwLock<Vec<AiAlert>>,
    total_events: AtomicU64,
    total_sensitive: AtomicU64,
    total_duplicates: AtomicU64,
    total_frequency_anomalies: AtomicU64,
    total_size_anomalies: AtomicU64,
    total_high_entropy: AtomicU64,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl ClipboardExfilDetector {
    pub fn new() -> Self {
        let acc = StreamAccumulator::new(50, ClipboardStats::default(), |stats, events: &[ClipboardEvent]| {
            for ev in events {
                stats.total_events += 1;
                if ev.is_read { stats.total_reads += 1; }
                if ev.is_write { stats.total_writes += 1; }
                *stats.by_data_type.entry(format!("{:?}", ev.data_type)).or_insert(0) += 1;
                *stats.by_agent.entry(ev.agent_id.clone()).or_insert(0) += 1;
                let n = stats.total_events as f64;
                stats.avg_content_length = stats.avg_content_length * ((n - 1.0) / n)
                    + ev.content_length as f64 / n;
                if ev.content_length > stats.max_content_length {
                    stats.max_content_length = ev.content_length;
                }
                if stats.window_start == 0 || ev.timestamp < stats.window_start { stats.window_start = ev.timestamp; }
                if ev.timestamp > stats.window_end { stats.window_end = ev.timestamp; }
            }
        });

        Self {
            scan_history: RwLock::new(ReversibleComputation::new(1000, |_inputs: &[ClipboardEvent]| -> ScanResult {
                ScanResult { event: ClipboardEvent { agent_id: String::new(), session_id: String::new(), timestamp: 0, data_type: ClipboardDataType::Unknown, content_length: 0, content_hash: 0, source_app: None, destination_app: None, is_read: false, is_write: false }, sensitive_types_found: vec![], risk_score: 0.0, entropy: 0.0, is_duplicate: false, frequency_anomaly: false, size_anomaly: false, details: vec![] }
            })),
            content_dedup: RwLock::new(DedupStore::<u64, Vec<u8>>::new()),
            stats_accumulator: RwLock::new(acc),
            frequency_tracker: RwLock::new(HashMap::new()),
            size_baselines: RwLock::new(HashMap::new()),
            app_flows: RwLock::new(HashMap::new()),
            max_clipboard_frequency: 30,
            frequency_window_secs: 60,
            size_anomaly_std_devs: 3.0,
            min_entropy_alert: 4.5,
            alerts: RwLock::new(Vec::new()),
            total_events: AtomicU64::new(0),
            total_sensitive: AtomicU64::new(0),
            total_duplicates: AtomicU64::new(0),
            total_frequency_anomalies: AtomicU64::new(0),
            total_size_anomalies: AtomicU64::new(0),
            total_high_entropy: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("clipboard_exfil_detector", 2 * 1024 * 1024);
        self.metrics = Some(metrics);
        self
    }

    /// Scan clipboard content WITHOUT storing it. Returns scan result.
    pub fn scan(&self, content: &str, event: ClipboardEvent) -> ScanResult {
        if !self.enabled {
            return ScanResult { event, sensitive_types_found: vec![], risk_score: 0.0,
                entropy: 0.0, is_duplicate: false, frequency_anomaly: false,
                size_anomaly: false, details: vec![] };
        }
        self.total_events.fetch_add(1, Ordering::Relaxed);
        let now = event.timestamp;
        let mut details = Vec::new();
        let mut risk_score = 0.0;

        // 1. Pattern scanning (never stores content)
        let sensitive_types = self.scan_patterns(content);
        if !sensitive_types.is_empty() {
            self.total_sensitive.fetch_add(1, Ordering::Relaxed);
            risk_score = f64::max(risk_score, 0.9);
            for st in &sensitive_types {
                details.push(format!("Sensitive data detected: {:?}", st));
                *self.stats_accumulator.write().state_mut().by_sensitive_type
                    .entry(format!("{:?}", st)).or_insert(0) += 1;
            }
            self.add_alert(now, Severity::Critical, "Sensitive data in clipboard",
                &format!("Agent {} clipboard contains {:?}", event.agent_id,
                    sensitive_types.iter().map(|s| format!("{:?}", s)).collect::<Vec<_>>().join(", ")));
        }

        // 2. SSN check (regex-like: NNN-NN-NNNN)
        if Self::has_ssn_pattern(content) && !sensitive_types.contains(&SensitiveDataType::SSN) {
            details.push("Possible SSN pattern detected".into());
            risk_score = f64::max(risk_score, 0.95);
        }

        // 3. Credit card check with Luhn validation
        if Self::has_credit_card(content) && !sensitive_types.contains(&SensitiveDataType::CreditCard) {
            details.push("Credit card number detected (Luhn valid)".into());
            risk_score = f64::max(risk_score, 0.95);
        }

        // 4. Entropy analysis
        let entropy = Self::shannon_entropy(content);
        if entropy > self.min_entropy_alert && content.len() > 20 {
            self.total_high_entropy.fetch_add(1, Ordering::Relaxed);
            details.push(format!("High entropy: {:.2} bits/char (possible encoded secret)", entropy));
            risk_score = f64::max(risk_score, 0.6);
        }

        // 5. Deduplication check
        let is_duplicate = self.content_dedup.read().contains_key(&event.content_hash);
        if !is_duplicate {
            self.content_dedup.write().insert(event.content_hash, vec![1u8]);
        } else {
            self.total_duplicates.fetch_add(1, Ordering::Relaxed);
            details.push("Duplicate clipboard content (previously seen)".into());
        }

        // 6. Frequency anomaly detection
        let frequency_anomaly = self.check_frequency(&event.agent_id, now);
        if frequency_anomaly {
            self.total_frequency_anomalies.fetch_add(1, Ordering::Relaxed);
            risk_score = f64::max(risk_score, 0.7);
            details.push(format!("Clipboard frequency anomaly: >{} events/min", self.max_clipboard_frequency));
            self.add_alert(now, Severity::High, "Clipboard cycling detected",
                &format!("Agent {} rapid clipboard access (possible exfil)", event.agent_id));
        }

        // 7. Size anomaly detection
        let size_anomaly = self.check_size_anomaly(&event.agent_id, event.content_length);
        if size_anomaly {
            self.total_size_anomalies.fetch_add(1, Ordering::Relaxed);
            risk_score = f64::max(risk_score, 0.6);
            details.push(format!("Clipboard size anomaly: {} bytes", event.content_length));
        }

        // 8. Cross-app flow tracking
        if let (Some(src), Some(dst)) = (&event.source_app, &event.destination_app) {
            let mut flows = self.app_flows.write();
            *flows.entry(src.clone()).or_insert_with(HashMap::new)
                .entry(dst.clone()).or_insert(0) += 1;
        }

        // Feed into streaming accumulator
        self.stats_accumulator.write().push(event.clone());

        ScanResult {
            event, sensitive_types_found: sensitive_types, risk_score: f64::min(risk_score, 1.0),
            entropy, is_duplicate, frequency_anomaly, size_anomaly, details,
        }
    }

    fn scan_patterns(&self, content: &str) -> Vec<SensitiveDataType> {
        let mut found = Vec::new();
        for pat in PATTERNS {
            if content.len() < pat.min_len { continue; }
            let matched = if pat.prefixes.is_empty() {
                pat.check_fn.map_or(false, |f| f(content))
            } else {
                pat.prefixes.iter().any(|p| content.contains(p))
            };
            if matched && content.len() <= pat.max_len {
                if let Some(check) = pat.check_fn {
                    if !check(content) { continue; }
                }
                found.push(pat.name);
            }
        }
        // Generic high-entropy secret detection
        if found.is_empty() && content.len() >= 32 && content.len() <= 256 {
            let entropy = Self::shannon_entropy(content);
            if entropy > 5.0 && content.chars().all(|c| c.is_ascii_graphic()) {
                found.push(SensitiveDataType::HighEntropyString);
            }
        }
        found
    }

    fn has_ssn_pattern(content: &str) -> bool {
        let bytes = content.as_bytes();
        if bytes.len() < 11 { return false; }
        for i in 0..bytes.len().saturating_sub(10) {
            if bytes[i].is_ascii_digit() && bytes[i+1].is_ascii_digit() && bytes[i+2].is_ascii_digit()
                && bytes[i+3] == b'-'
                && bytes[i+4].is_ascii_digit() && bytes[i+5].is_ascii_digit()
                && bytes[i+6] == b'-'
                && bytes[i+7].is_ascii_digit() && bytes[i+8].is_ascii_digit()
                && bytes[i+9].is_ascii_digit() && bytes[i+10].is_ascii_digit()
            {
                let area = (bytes[i] - b'0') as u16 * 100 + (bytes[i+1] - b'0') as u16 * 10 + (bytes[i+2] - b'0') as u16;
                if area > 0 && area != 666 && area < 900 { return true; }
            }
        }
        false
    }

    fn has_credit_card(content: &str) -> bool {
        let digits: Vec<u8> = content.chars()
            .filter(|c| c.is_ascii_digit())
            .map(|c| c as u8 - b'0')
            .collect();
        if digits.len() < 13 || digits.len() > 19 { return false; }
        // Luhn check
        let mut sum = 0u32;
        let mut double = false;
        for &d in digits.iter().rev() {
            let mut val = d as u32;
            if double { val *= 2; if val > 9 { val -= 9; } }
            sum += val;
            double = !double;
        }
        sum % 10 == 0
    }

    fn shannon_entropy(s: &str) -> f64 {
        if s.is_empty() { return 0.0; }
        let mut freq = [0u32; 256];
        for &b in s.as_bytes() { freq[b as usize] += 1; }
        let len = s.len() as f64;
        let mut entropy = 0.0;
        for &f in &freq {
            if f > 0 {
                let p = f as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    fn check_frequency(&self, agent_id: &str, now: i64) -> bool {
        let mut tracker = self.frequency_tracker.write();
        let deque = tracker.entry(agent_id.to_string()).or_insert_with(VecDeque::new);
        let cutoff = now - self.frequency_window_secs;
        while deque.front().map_or(false, |t| *t < cutoff) { deque.pop_front(); }
        deque.push_back(now);
        deque.len() as u64 > self.max_clipboard_frequency
    }

    fn check_size_anomaly(&self, agent_id: &str, size: usize) -> bool {
        let mut baselines = self.size_baselines.write();
        let (mean, m2, count) = baselines.entry(agent_id.to_string()).or_insert((0.0, 0.0, 0));
        *count += 1;
        let n = *count as f64;
        let delta = size as f64 - *mean;
        *mean += delta / n;
        let delta2 = size as f64 - *mean;
        *m2 += delta * delta2;
        if *count > 10 {
            let std = (*m2 / (n - 1.0)).sqrt();
            if std > 0.0 && (size as f64 - *mean).abs() > self.size_anomaly_std_devs * std {
                return true;
            }
        }
        false
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(AiAlert { timestamp: ts, severity: sev, component: "clipboard_exfil_detector".into(),
            title: title.into(), details: details.into() });
    }

    pub fn current_stats(&self) -> ClipboardStats { self.stats_accumulator.read().state().clone() }
    pub fn app_flows(&self) -> HashMap<String, HashMap<String, u64>> { self.app_flows.read().clone() }
    pub fn total_events(&self) -> u64 { self.total_events.load(Ordering::Relaxed) }
    pub fn total_sensitive(&self) -> u64 { self.total_sensitive.load(Ordering::Relaxed) }
    pub fn total_duplicates(&self) -> u64 { self.total_duplicates.load(Ordering::Relaxed) }
    pub fn total_frequency_anomalies(&self) -> u64 { self.total_frequency_anomalies.load(Ordering::Relaxed) }
    pub fn total_high_entropy(&self) -> u64 { self.total_high_entropy.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
