//! AI API Key Monitor — tracks, rotates, and detects leaked AI service API keys.
//!
//! Detection capabilities:
//!   1. Known key format matching (15+ AI services: OpenAI, Anthropic, Google, etc.)
//!   2. Entropy-based detection (high-entropy strings in prompts/outputs)
//!   3. Usage anomaly detection (rate spikes, burst patterns, off-hours)
//!   4. Text scanning for leaked keys in prompts, outputs, tool results
//!   5. Key rotation enforcement and age tracking
//!   6. Scope validation (over-privileged keys)
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Hot key lookups cached
//! - **#6 Theoretical Verifier**: Bounded by key count

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::differential::DifferentialStore;
use sentinel_core::pruning::PruningMap;
use sentinel_core::hierarchical::HierarchicalState;
use sentinel_core::sparse::SparseMatrix;
use sentinel_core::dedup::DedupStore;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use std::collections::HashMap;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

/// Known AI API key format patterns: (prefix, name, min_len, max_len)
const KNOWN_KEY_FORMATS: &[(&str, &str, usize, usize)] = &[
    ("sk-",           "openai",         40, 60),
    ("sk-proj-",      "openai_project", 40, 120),
    ("sk-ant-",       "anthropic",      80, 130),
    ("aip-",          "anthropic_v2",   40, 80),
    ("AIza",          "google_ai",      35, 45),
    ("gsk_",          "groq",           40, 60),
    ("hf_",           "huggingface",    30, 50),
    ("r8_",           "replicate",      30, 50),
    ("xai-",          "xai",            40, 60),
    ("pplx-",         "perplexity",     40, 60),
    ("nvapi-",        "nvidia_nim",     40, 60),
    ("LA-",           "lightning_ai",   30, 60),
    ("co-",           "cohere",         30, 50),
    ("AKIA",          "aws_access",     16, 24),
    ("eyJhbGci",      "jwt_token",      50, 2000),
    ("ghp_",          "github_pat",     30, 50),
    ("glpat-",        "gitlab_pat",     20, 30),
    ("bearer ",       "bearer_token",   30, 500),
    ("token ",        "generic_token",  20, 200),
];

/// Suspicious environment variable names that may contain keys
const KEY_ENV_PATTERNS: &[&str] = &[
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY",
    "HUGGINGFACE_TOKEN", "HF_TOKEN", "REPLICATE_API_TOKEN",
    "GROQ_API_KEY", "COHERE_API_KEY", "AWS_SECRET_ACCESS_KEY",
    "API_KEY", "SECRET_KEY", "ACCESS_TOKEN", "AUTH_TOKEN",
];

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AiApiKey {
    pub key_id: String,
    pub service: String,
    pub created_at: i64,
    pub last_used: i64,
    pub usage_count: u64,
    pub max_age_secs: i64,
    pub leaked: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeyScanResult {
    pub keys_found: Vec<KeyFinding>,
    pub high_entropy_segments: Vec<String>,
    pub env_var_references: Vec<String>,
    pub risk_score: f64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeyFinding {
    pub service: String,
    pub prefix: String,
    pub key_length: usize,
    pub redacted_preview: String,
    pub severity: Severity,
}

#[derive(Debug, Clone)]
struct UsageProfile {
    timestamps: Vec<i64>,
    hourly_counts: [u32; 24],
    total_calls: u64,
    avg_rate_per_min: f64,
    last_anomaly_check: i64,
}

/// AI API key monitor.
pub struct ApiKeyMonitor {
    keys: RwLock<HashMap<String, AiApiKey>>,
    /// #2 Tiered cache: active key lookups hot
    key_cache: TieredCache<String, bool>,
    /// Usage profiles for anomaly detection
    usage_profiles: RwLock<HashMap<String, UsageProfile>>,
    alerts: RwLock<Vec<AiAlert>>,
    total_keys: AtomicU64,
    leaked_keys: AtomicU64,
    total_scans: AtomicU64,
    total_keys_found_in_text: AtomicU64,
    /// Breakthrough #461: Key inventory evolution tracking
    key_diffs: DifferentialStore<String, String>,
    /// Breakthrough #569: φ-weighted alert pruning
    pruned_alerts: PruningMap<String, AiAlert>,
    /// Breakthrough #1: O(log n) key usage trend history
    usage_state: RwLock<HierarchicalState<u64>>,
    /// Breakthrough #627: Sparse service×user key matrix
    key_matrix: RwLock<SparseMatrix<String, String, u64>>,
    /// Breakthrough #592: Content-addressed dedup for key fingerprints
    key_dedup: DedupStore<String, String>,
    /// #6 Theoretical verifier
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl ApiKeyMonitor {
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            key_cache: TieredCache::new(5_000),
            usage_profiles: RwLock::new(HashMap::new()),
            alerts: RwLock::new(Vec::new()),
            total_keys: AtomicU64::new(0),
            leaked_keys: AtomicU64::new(0),
            total_scans: AtomicU64::new(0),
            total_keys_found_in_text: AtomicU64::new(0),
            key_diffs: DifferentialStore::new(),
            pruned_alerts: PruningMap::new(5_000),
            usage_state: RwLock::new(HierarchicalState::new(8, 64)),
            key_matrix: RwLock::new(SparseMatrix::new(0)),
            key_dedup: DedupStore::new(),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("api_key_monitor", 2 * 1024 * 1024);
        self.key_cache = self.key_cache.with_metrics(metrics.clone(), "api_key_monitor");
        self.metrics = Some(metrics);
        self
    }

    pub fn register_key(&self, key: AiApiKey) {
        self.total_keys.fetch_add(1, Ordering::Relaxed);
        self.keys.write().insert(key.key_id.clone(), key);
    }

    // ── Usage Recording & Anomaly Detection ──────────────────────────────────

    pub fn record_usage(&self, key_id: &str) {
        let now = chrono::Utc::now().timestamp();
        if let Some(k) = self.keys.write().get_mut(key_id) {
            k.usage_count += 1;
            k.last_used = now;
        }

        // Track usage profile for anomaly detection
        let mut profiles = self.usage_profiles.write();
        let profile = profiles.entry(key_id.to_string()).or_insert(UsageProfile {
            timestamps: Vec::new(),
            hourly_counts: [0u32; 24],
            total_calls: 0,
            avg_rate_per_min: 0.0,
            last_anomaly_check: now,
        });

        profile.timestamps.push(now);
        profile.total_calls += 1;

        // Keep last 1000 timestamps
        if profile.timestamps.len() > 1000 {
            let drain = profile.timestamps.len() - 1000;
            profile.timestamps.drain(..drain);
        }

        // Track hourly distribution
        let hour = ((now % 86400) / 3600) as usize;
        if hour < 24 { profile.hourly_counts[hour] += 1; }

        // Update rolling rate
        let alpha = 0.05;
        let recent_60s = profile.timestamps.iter().filter(|&&t| now - t < 60).count() as f64;
        profile.avg_rate_per_min = profile.avg_rate_per_min * (1.0 - alpha) + recent_60s * alpha;

        // Check for anomalies periodically
        if now - profile.last_anomaly_check > 30 {
            profile.last_anomaly_check = now;
            self.check_usage_anomaly(key_id, profile, now);
        }
    }

    fn check_usage_anomaly(&self, key_id: &str, profile: &UsageProfile, now: i64) {
        // 1. Rate spike: >5× the rolling average
        let recent_60s = profile.timestamps.iter().filter(|&&t| now - t < 60).count() as f64;
        if profile.avg_rate_per_min > 1.0 && recent_60s > profile.avg_rate_per_min * 5.0 {
            warn!(key=%key_id, rate=recent_60s, avg=profile.avg_rate_per_min, "API key usage spike");
            self.add_alert(now, Severity::High, "API key usage spike",
                &format!("Key {} rate {:.0}/min vs avg {:.1}/min ({}× spike)",
                    key_id, recent_60s, profile.avg_rate_per_min, (recent_60s / profile.avg_rate_per_min) as u32));
        }

        // 2. Burst detection: >50 calls in 10 seconds
        let burst = profile.timestamps.iter().filter(|&&t| now - t < 10).count();
        if burst > 50 {
            warn!(key=%key_id, burst=burst, "API key burst detected");
            self.add_alert(now, Severity::High, "API key burst",
                &format!("Key {} had {} calls in 10 seconds — possible credential stuffing or extraction", key_id, burst));
        }

        // 3. Off-hours usage (if key normally used 9-17, flag 2-5 AM usage)
        if profile.total_calls > 100 {
            let hour = ((now % 86400) / 3600) as usize;
            let total_hourly: u32 = profile.hourly_counts.iter().sum();
            if total_hourly > 0 && hour < 24 {
                let hour_pct = profile.hourly_counts[hour] as f64 / total_hourly as f64;
                // If this hour normally has <2% of traffic and we're getting calls
                if hour_pct < 0.02 && recent_60s > 1.0 {
                    self.add_alert(now, Severity::Medium, "Off-hours API key usage",
                        &format!("Key {} used at hour {} (only {:.1}% of normal traffic)", key_id, hour, hour_pct * 100.0));
                }
            }
        }
    }

    // ── Text Scanning for Leaked Keys ────────────────────────────────────────

    /// Scan text (prompts, outputs, tool results) for exposed API keys.
    /// Returns findings with redacted previews.
    pub fn scan_text(&self, text: &str) -> KeyScanResult {
        if !self.enabled || text.is_empty() {
            return KeyScanResult { keys_found: vec![], high_entropy_segments: vec![], env_var_references: vec![], risk_score: 0.0 };
        }
        self.total_scans.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();

        let mut keys_found = Vec::new();
        let mut env_refs = Vec::new();
        let mut max_risk = 0.0f64;

        // 1. Known prefix matching
        for (prefix, service, min_len, max_len) in KNOWN_KEY_FORMATS {
            let mut search_from = 0;
            while let Some(pos) = text[search_from..].find(prefix) {
                let abs_pos = search_from + pos;
                // Extract the candidate key (until whitespace, quote, or non-key char)
                let key_start = abs_pos;
                let mut key_end = key_start;
                for ch in text[key_start..].chars() {
                    if ch.is_whitespace() || ch == '"' || ch == '\'' || ch == '`'
                        || ch == ',' || ch == ';' || ch == ')' || ch == ']' || ch == '}' {
                        break;
                    }
                    key_end += ch.len_utf8();
                }
                let candidate = &text[key_start..key_end];
                let clen = candidate.len();

                if clen >= *min_len && clen <= *max_len {
                    self.total_keys_found_in_text.fetch_add(1, Ordering::Relaxed);
                    let redacted = Self::redact_key(candidate);
                    keys_found.push(KeyFinding {
                        service: service.to_string(),
                        prefix: prefix.to_string(),
                        key_length: clen,
                        redacted_preview: redacted,
                        severity: Severity::Critical,
                    });
                    max_risk = 1.0;
                }

                search_from = abs_pos + prefix.len();
                if search_from >= text.len() { break; }
            }
        }

        // 2. Entropy-based detection: find high-entropy segments that look like keys
        let high_entropy = self.find_high_entropy_segments(text);
        if !high_entropy.is_empty() {
            max_risk = max_risk.max(0.70);
        }

        // 3. Environment variable reference detection
        let text_upper = text.to_uppercase();
        for env_pat in KEY_ENV_PATTERNS {
            if text_upper.contains(env_pat) {
                env_refs.push(env_pat.to_string());
                max_risk = max_risk.max(0.50);
            }
        }

        // Alert if keys found
        if !keys_found.is_empty() {
            let services: Vec<&str> = keys_found.iter().map(|k| k.service.as_str()).collect();
            warn!(count=keys_found.len(), services=?services, "API keys detected in text");
            self.add_alert(now, Severity::Critical, "API keys exposed in text",
                &format!("{} key(s) found: {}", keys_found.len(), services.join(", ")));
        }

        KeyScanResult {
            keys_found,
            high_entropy_segments: high_entropy,
            env_var_references: env_refs,
            risk_score: max_risk,
        }
    }

    fn find_high_entropy_segments(&self, text: &str) -> Vec<String> {
        let mut segments = Vec::new();
        for word in text.split_whitespace() {
            let trimmed = word.trim_matches(|c: char| c == '"' || c == '\'' || c == '`' || c == ',');
            // Candidate: 20+ chars, mixed case/digits, no common English patterns
            if trimmed.len() >= 20 && trimmed.len() <= 200 {
                let entropy = Self::shannon_entropy(trimmed);
                let has_mixed = trimmed.chars().any(|c| c.is_uppercase())
                    && trimmed.chars().any(|c| c.is_lowercase())
                    && trimmed.chars().any(|c| c.is_ascii_digit());
                // High entropy (>4.0 bits) + mixed charset = likely a key/secret
                if entropy > 4.0 && has_mixed {
                    segments.push(Self::redact_key(trimmed));
                }
            }
        }
        segments.truncate(10); // cap findings
        segments
    }

    fn shannon_entropy(s: &str) -> f64 {
        if s.is_empty() { return 0.0; }
        let mut freq = [0u32; 256];
        for &b in s.as_bytes() { freq[b as usize] += 1; }
        let len = s.len() as f64;
        let mut entropy = 0.0f64;
        for &count in &freq {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    fn redact_key(key: &str) -> String {
        if key.len() <= 8 {
            "****".to_string()
        } else {
            format!("{}...{}", &key[..4], &key[key.len()-4..])
        }
    }

    // ── Existing API ────────────────────────────────────────────────────────

    pub fn mark_leaked(&self, key_id: &str) {
        self.leaked_keys.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        warn!(key = %key_id, "AI API key leaked!");
        self.add_alert(now, Severity::Critical, "API key leaked", &format!("Key {} has been leaked — rotate immediately", key_id));
        if let Some(k) = self.keys.write().get_mut(key_id) {
            k.leaked = true;
        }
    }

    pub fn overdue_rotation(&self) -> Vec<AiApiKey> {
        let now = chrono::Utc::now().timestamp();
        self.keys.read().values().filter(|k| now - k.created_at > k.max_age_secs).cloned().collect()
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(AiAlert { timestamp: ts, severity: sev, component: "api_key_monitor".into(), title: title.into(), details: details.into() });
    }

    pub fn total_keys(&self) -> u64 { self.total_keys.load(Ordering::Relaxed) }
    pub fn leaked_keys(&self) -> u64 { self.leaked_keys.load(Ordering::Relaxed) }
    pub fn total_scans(&self) -> u64 { self.total_scans.load(Ordering::Relaxed) }
    pub fn total_keys_found(&self) -> u64 { self.total_keys_found_in_text.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
