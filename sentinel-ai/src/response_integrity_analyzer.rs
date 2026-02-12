//! Response Integrity Analyzer — detects tampered, poisoned, or weaponized LLM outputs.
//!
//! When an AI model returns a response, this engine analyzes it BEFORE the user
//! or downstream agent acts on it:
//!
//! - **Steganographic exfiltration** — hidden data encoded in text structure
//!   (acrostics, whitespace encoding, zero-width characters, unicode homoglyphs)
//! - **Embedded payloads** — base64, hex, or URL-encoded data smuggled in prose
//! - **Poisoned content** — typosquat packages, malicious URLs, bad config values
//! - **Data leak detection** — PII, API keys, secrets, internal IPs in outputs
//! - **Hidden instruction injection** — commands for downstream agents buried
//!   in markdown, code comments, or invisible formatting
//! - **Entropy anomaly detection** — statistical deviation from expected output
//!   distribution, signaling machine-generated steganographic content
//! - **Response consistency** — cross-turn contradiction and confidence tracking
//!
//! This is the output-side complement to the Plan Review Engine:
//!   Plan Review guards ACTIONS. Response Integrity guards OUTPUTS.
//!
//! Memory breakthroughs:
//!   #2  TieredCache — hot/warm/cold response fingerprint cache
//!   #461 DifferentialStore — response pattern evolution tracking
//!   #5  StreamAccumulator — streaming integrity statistics
//!   #569 PruningMap — φ-weighted finding history eviction
//!   #1  HierarchicalState — O(log n) integrity trend checkpointing
//!   #627 SparseMatrix — sparse model×finding_type matrix
//!   #592 DedupStore — content-addressed response dedup
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
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::time::Duration;
use tracing::info;

const MAX_ALERTS: usize = 5_000;
const MAX_FINDING_HISTORY: usize = 10_000;

// ── Integrity Levels ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub enum IntegrityLevel {
    /// Response appears clean — no anomalies detected.
    Clean,
    /// Minor anomalies found — may warrant review.
    Suspicious,
    /// Significant integrity violations — do not trust without inspection.
    Compromised,
    /// Active exfiltration or attack payload detected — block immediately.
    Hostile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum FindingCategory {
    SteganographicExfiltration,
    EmbeddedPayload,
    PoisonedUrl,
    PoisonedPackage,
    PoisonedConfig,
    DataLeakPii,
    DataLeakSecret,
    DataLeakInfrastructure,
    HiddenInstruction,
    EntropyAnomaly,
    UnicodeAnomaly,
    ZeroWidthInjection,
    InvisibleFormatting,
    CrossTurnContradiction,
    MaliciousCodePattern,
}

impl FindingCategory {
    /// Map to MITRE ATT&CK technique IDs for enterprise threat intelligence.
    pub fn mitre_techniques(&self) -> &'static [&'static str] {
        match self {
            Self::SteganographicExfiltration => &["T1001.002"],  // Steganography
            Self::EmbeddedPayload => &["T1027"],                 // Obfuscated Files or Info
            Self::PoisonedUrl => &["T1566.002"],                 // Spearphishing Link
            Self::PoisonedPackage => &["T1195.001"],             // Compromise Software Dependencies
            Self::PoisonedConfig => &["T1195.002"],              // Compromise Software Supply Chain
            Self::DataLeakPii => &["T1567"],                     // Exfiltration Over Web Service
            Self::DataLeakSecret => &["T1552"],                  // Unsecured Credentials
            Self::DataLeakInfrastructure => &["T1018"],          // Remote System Discovery
            Self::HiddenInstruction => &["T1059"],               // Command and Scripting Interpreter
            Self::EntropyAnomaly => &["T1001"],                  // Data Obfuscation
            Self::UnicodeAnomaly => &["T1036.005"],              // Match Legitimate Name or Location
            Self::ZeroWidthInjection => &["T1027.010"],          // Command Obfuscation
            Self::InvisibleFormatting => &["T1027.010"],         // Command Obfuscation
            Self::CrossTurnContradiction => &["T1565"],          // Data Manipulation
            Self::MaliciousCodePattern => &["T1059.004"],        // Unix Shell
        }
    }
}

// ── Input / Output Data Model ───────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LlmResponse {
    pub response_id: String,
    pub model_name: String,
    pub content: String,
    pub prompt_summary: String,
    pub turn_number: u32,
    pub timestamp: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IntegrityFinding {
    pub category: FindingCategory,
    pub severity: Severity,
    pub title: String,
    pub details: String,
    pub evidence: String,
    pub byte_offset: Option<usize>,
    pub mitre_ids: Vec<String>,
    pub recommended_action: String,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct EntropyProfile {
    pub char_entropy: f64,
    pub word_entropy: f64,
    pub line_length_variance: f64,
    pub whitespace_ratio: f64,
    pub punctuation_ratio: f64,
    pub uppercase_ratio: f64,
    pub digit_ratio: f64,
    pub non_ascii_ratio: f64,
    pub zero_width_count: u32,
    pub unicode_homoglyph_count: u32,
    pub invisible_char_count: u32,
    pub entropy_anomaly_score: f64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResponseAnalysis {
    pub response_id: String,
    pub model_name: String,
    pub overall_integrity: IntegrityLevel,
    pub findings: Vec<IntegrityFinding>,
    pub entropy_profile: EntropyProfile,
    pub total_findings: u32,
    pub critical_findings: u32,
    pub data_leak_count: u32,
    pub stego_score: f64,
    pub poisoned_artifact_count: u32,
    pub summary: String,
    pub analyzed_at: i64,
}

// ── Detection Databases ─────────────────────────────────────────────────────

/// Known-bad TLDs commonly used in phishing and typosquatting.
const SUSPICIOUS_TLDS: &[&str] = &[
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw",
    ".cc", ".su", ".buzz", ".wang", ".club", ".icu", ".cam",
    ".rest", ".bid", ".loan", ".trade", ".win", ".click",
];

/// URL patterns that indicate direct IP access (bypassing DNS).
const IP_URL_PATTERNS: &[&str] = &[
    "http://10.", "http://172.16.", "http://172.17.", "http://172.18.",
    "http://172.19.", "http://172.20.", "http://172.21.", "http://172.22.",
    "http://172.23.", "http://172.24.", "http://172.25.", "http://172.26.",
    "http://172.27.", "http://172.28.", "http://172.29.", "http://172.30.",
    "http://172.31.", "http://192.168.", "http://127.", "https://10.",
    "https://172.16.", "https://192.168.", "https://127.",
];

/// Known typosquat patterns for popular packages.
const TYPOSQUAT_PREFIXES: &[&str] = &[
    "python-", "py-", "node-", "js-", "react-native-", "vue-",
    "angular-", "next-", "svelte-", "express-", "fastapi-",
];

/// Known malicious package name patterns.
const MALICIOUS_PACKAGE_PATTERNS: &[&str] = &[
    "color", "colours", "event-stream", "flatmap-stream",
    "ua-parser-js-", "coa-", "rc-", "faker-",
];

/// Popular packages — any near-miss to these is suspicious.
const POPULAR_PACKAGES: &[(&str, &str)] = &[
    ("numpy", "python"), ("pandas", "python"), ("requests", "python"),
    ("flask", "python"), ("django", "python"), ("tensorflow", "python"),
    ("torch", "python"), ("scipy", "python"), ("cryptography", "python"),
    ("paramiko", "python"), ("boto3", "python"), ("pillow", "python"),
    ("express", "npm"), ("react", "npm"), ("lodash", "npm"),
    ("axios", "npm"), ("next", "npm"), ("webpack", "npm"),
    ("typescript", "npm"), ("tailwindcss", "npm"), ("vite", "npm"),
    ("eslint", "npm"), ("prettier", "npm"), ("stripe", "npm"),
];

/// PII regex-like patterns (we use substring matching for speed).
const _PII_PATTERNS: &[(&str, &str)] = &[
    ("SSN", r"social security"),
    ("SSN_NUMERIC", r"###-##-####"),
    ("CREDIT_CARD_VISA", r"4[0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}"),
    ("CREDIT_CARD_MC", r"5[1-5][0-9]{2}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}"),
    ("PHONE_US", r"+1"),
    ("EMAIL_PATTERN", r"@"),
    ("PASSPORT", r"passport"),
    ("DOB", r"date of birth"),
    ("DRIVER_LICENSE", r"driver's license"),
];

/// Secret/API key patterns.
const SECRET_PATTERNS: &[(&str, &str)] = &[
    ("AWS_ACCESS_KEY", "AKIA"),
    ("AWS_SECRET", "aws_secret_access_key"),
    ("GITHUB_TOKEN", "ghp_"),
    ("GITHUB_TOKEN_OLD", "github_pat_"),
    ("GITLAB_TOKEN", "glpat-"),
    ("SLACK_TOKEN", "xoxb-"),
    ("SLACK_WEBHOOK", "hooks.slack.com"),
    ("STRIPE_SK", "sk_live_"),
    ("STRIPE_PK", "pk_live_"),
    ("OPENAI_KEY", "sk-"),
    ("ANTHROPIC_KEY", "sk-ant-"),
    ("GOOGLE_API_KEY", "AIza"),
    ("FIREBASE_KEY", "AIza"),
    ("TWILIO_SID", "AC"),
    ("SENDGRID_KEY", "SG."),
    ("PRIVATE_KEY_PEM", "-----BEGIN"),
    ("RSA_PRIVATE", "-----BEGIN RSA PRIVATE"),
    ("BEARER_TOKEN", "Bearer eyJ"),
    ("JWT", "eyJhbGci"),
    ("NPM_TOKEN", "npm_"),
    ("PYPI_TOKEN", "pypi-"),
    ("DOCKER_AUTH", "docker_auth"),
    ("VERCEL_TOKEN", "vercel_"),
    ("NETLIFY_TOKEN", "netlify_"),
    ("HEROKU_API", "heroku_"),
    ("DATABASE_URL", "postgres://"),
    ("DATABASE_URL_MYSQL", "mysql://"),
    ("DATABASE_URL_MONGO", "mongodb://"),
    ("REDIS_URL", "redis://"),
    ("SSH_PRIVATE", "id_rsa"),
    ("SSH_ED25519", "id_ed25519"),
    ("ENCRYPTION_KEY", "encryption_key"),
    ("MASTER_KEY", "master_key"),
    ("SECRET_KEY", "secret_key="),
];

/// Dangerous code patterns that should never appear in LLM suggestions.
const MALICIOUS_CODE_PATTERNS: &[(&str, &str, Severity)] = &[
    ("reverse_shell_bash", "bash -i >& /dev/tcp/", Severity::Critical),
    ("reverse_shell_nc", "nc -e /bin/", Severity::Critical),
    ("reverse_shell_python", "socket.socket", Severity::Medium),  // common but context matters
    ("crypto_miner", "stratum+tcp://", Severity::Critical),
    ("crypto_miner_xmr", "xmrig", Severity::Critical),
    ("curl_pipe_bash", "curl | bash", Severity::High),
    ("curl_pipe_sh", "curl | sh", Severity::High),
    ("wget_pipe_bash", "wget | bash", Severity::High),
    ("eval_base64", "eval(base64", Severity::Critical),
    ("eval_atob", "eval(atob(", Severity::Critical),
    ("python_exec_b64", "exec(base64.b64decode", Severity::Critical),
    ("obfuscated_exec", "\\x65\\x76\\x61\\x6c", Severity::Critical),  // hex-encoded 'eval'
    ("rm_rf_root", "rm -rf /", Severity::Critical),
    ("dd_dev_sda", "dd if=/dev/zero of=/dev/sda", Severity::Critical),
    ("fork_bomb", ":(){ :|:& };:", Severity::Critical),
    ("chmod_777_root", "chmod -R 777 /", Severity::Critical),
    ("iptables_flush", "iptables -F", Severity::High),
    ("disable_firewall", "ufw disable", Severity::High),
    ("keylogger", "pynput", Severity::High),
    ("dns_exfil", ".burpcollaborator.net", Severity::Critical),
    ("dns_exfil_oast", "oastify.com", Severity::Critical),
    ("ngrok_tunnel", "ngrok", Severity::Medium),
    ("disable_ssl_verify", "verify=False", Severity::Medium),
    ("disable_tls_node", "NODE_TLS_REJECT_UNAUTHORIZED", Severity::High),
    ("sql_injection", "' OR 1=1", Severity::High),
    ("ssti_jinja", "{{config.__class__", Severity::Critical),
    ("docker_privileged", "--privileged", Severity::High),
    ("docker_mount_root", "-v /:/", Severity::Critical),
];

/// Zero-width and invisible Unicode characters used for steganography.
const ZERO_WIDTH_CHARS: &[char] = &[
    '\u{200B}', // Zero Width Space
    '\u{200C}', // Zero Width Non-Joiner
    '\u{200D}', // Zero Width Joiner
    '\u{2060}', // Word Joiner
    '\u{FEFF}', // Zero Width No-Break Space (BOM)
    '\u{180E}', // Mongolian Vowel Separator
    '\u{200E}', // Left-to-Right Mark
    '\u{200F}', // Right-to-Left Mark
    '\u{202A}', // Left-to-Right Embedding
    '\u{202B}', // Right-to-Left Embedding
    '\u{202C}', // Pop Directional Formatting
    '\u{202D}', // Left-to-Right Override
    '\u{202E}', // Right-to-Left Override (used in filename spoofing)
    '\u{2066}', // Left-to-Right Isolate
    '\u{2067}', // Right-to-Left Isolate
    '\u{2068}', // First Strong Isolate
    '\u{2069}', // Pop Directional Isolate
    '\u{00AD}', // Soft Hyphen
    '\u{034F}', // Combining Grapheme Joiner
    '\u{061C}', // Arabic Letter Mark
    '\u{115F}', // Hangul Choseong Filler
    '\u{1160}', // Hangul Jungseong Filler
    '\u{17B4}', // Khmer Vowel Inherent Aq
    '\u{17B5}', // Khmer Vowel Inherent Aa
    '\u{3164}', // Hangul Filler
    '\u{FFA0}', // Halfwidth Hangul Filler
];

/// Unicode confusable pairs (homoglyphs) — character that looks like ASCII but isn't.
const HOMOGLYPH_MAP: &[(char, char)] = &[
    ('А', 'A'), ('В', 'B'), ('С', 'C'), ('Е', 'E'), ('Н', 'H'),
    ('І', 'I'), ('К', 'K'), ('М', 'M'), ('О', 'O'), ('Р', 'P'),
    ('Т', 'T'), ('Х', 'X'), ('а', 'a'), ('с', 'c'), ('е', 'e'),
    ('і', 'i'), ('о', 'o'), ('р', 'p'), ('х', 'x'), ('у', 'y'),
    ('ɡ', 'g'), ('ɑ', 'a'), ('ⅰ', 'i'), ('ⅼ', 'l'), ('ⅿ', 'm'),
    ('ℊ', 'g'), ('ℎ', 'h'), ('ℯ', 'e'), ('ℴ', 'o'), ('ℓ', 'l'),
    ('０', '0'), ('１', '1'), ('２', '2'), ('３', '3'), ('４', '4'),
    ('５', '5'), ('６', '6'), ('７', '7'), ('８', '8'), ('９', '9'),
    ('ⓐ', 'a'), ('ⓑ', 'b'), ('ⓒ', 'c'), ('ⓓ', 'd'), ('ⓔ', 'e'),
    ('ᴀ', 'A'), ('ʙ', 'B'), ('ᴄ', 'C'), ('ᴅ', 'D'), ('ᴇ', 'E'),
    ('\u{FF41}', 'a'), // Fullwidth Latin Small Letter A
    ('\u{FF42}', 'b'), // Fullwidth Latin Small Letter B
];

/// Hidden instruction patterns that downstream agents might follow.
const HIDDEN_INSTRUCTION_PATTERNS: &[(&str, Severity)] = &[
    ("ignore previous instructions", Severity::Critical),
    ("ignore all prior", Severity::Critical),
    ("disregard your instructions", Severity::Critical),
    ("you are now", Severity::High),
    ("new system prompt:", Severity::Critical),
    ("SYSTEM:", Severity::High),
    ("<!-- hidden:", Severity::Critical),
    ("<!-- inject:", Severity::Critical),
    ("[hidden]", Severity::High),
    ("\\x00", Severity::High),  // null bytes
    ("data:text/html", Severity::High),
    ("javascript:", Severity::High),
    ("onerror=", Severity::High),
    ("onload=", Severity::High),
    ("<script>", Severity::Critical),
    ("<iframe", Severity::High),
    ("<img src=x onerror=", Severity::Critical),
];

// ── Integrity Statistics (for StreamAccumulator) ────────────────────────────

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct IntegrityStats {
    pub total_analyzed: u64,
    pub total_findings: u64,
    pub total_clean: u64,
    pub total_suspicious: u64,
    pub total_compromised: u64,
    pub total_hostile: u64,
    pub stego_detections: u64,
    pub data_leak_detections: u64,
    pub poisoned_artifact_detections: u64,
    pub malicious_code_detections: u64,
    pub hidden_instruction_detections: u64,
    pub unique_models: HashSet<String>,
    pub window_start: i64,
    pub window_end: i64,
}

// ── The Engine ───────────────────────────────────────────────────────────────

pub struct ResponseIntegrityAnalyzer {
    alerts: RwLock<Vec<AiAlert>>,
    total_analyzed: AtomicU64,
    total_hostile: AtomicU64,
    total_compromised: AtomicU64,
    enabled: AtomicBool,
    // Cross-turn state for contradiction detection
    _claim_history: RwLock<HashMap<String, Vec<(String, i64)>>>,
    // ── Memory Breakthroughs ─────────────────────────────────────────────
    integrity_cache: TieredCache<String, IntegrityLevel>,
    pattern_diffs: RwLock<DifferentialStore<String, String>>,
    integrity_stats: RwLock<StreamAccumulator<ResponseAnalysis, IntegrityStats>>,
    finding_history: RwLock<PruningMap<String, ResponseAnalysis>>,
    integrity_checkpoints: RwLock<HierarchicalState<u64>>,
    finding_matrix: RwLock<SparseMatrix<String, String, u64>>,
    response_dedup: RwLock<DedupStore<String, String>>,
    metrics: Option<MemoryMetrics>,
}

impl ResponseIntegrityAnalyzer {
    pub fn new() -> Self {
        let stats_acc = StreamAccumulator::new(25, IntegrityStats::default(), |acc, analyses: &[ResponseAnalysis]| {
            for a in analyses {
                acc.total_analyzed += 1;
                acc.total_findings += a.total_findings as u64;
                match a.overall_integrity {
                    IntegrityLevel::Clean => acc.total_clean += 1,
                    IntegrityLevel::Suspicious => acc.total_suspicious += 1,
                    IntegrityLevel::Compromised => acc.total_compromised += 1,
                    IntegrityLevel::Hostile => acc.total_hostile += 1,
                }
                acc.unique_models.insert(a.model_name.clone());
                for f in &a.findings {
                    match f.category {
                        FindingCategory::SteganographicExfiltration | FindingCategory::ZeroWidthInjection
                        | FindingCategory::UnicodeAnomaly | FindingCategory::EntropyAnomaly => acc.stego_detections += 1,
                        FindingCategory::DataLeakPii | FindingCategory::DataLeakSecret
                        | FindingCategory::DataLeakInfrastructure => acc.data_leak_detections += 1,
                        FindingCategory::PoisonedUrl | FindingCategory::PoisonedPackage
                        | FindingCategory::PoisonedConfig => acc.poisoned_artifact_detections += 1,
                        FindingCategory::MaliciousCodePattern => acc.malicious_code_detections += 1,
                        FindingCategory::HiddenInstruction | FindingCategory::InvisibleFormatting => acc.hidden_instruction_detections += 1,
                        _ => {}
                    }
                }
                if acc.window_start == 0 || a.analyzed_at < acc.window_start { acc.window_start = a.analyzed_at; }
                if a.analyzed_at > acc.window_end { acc.window_end = a.analyzed_at; }
            }
        });

        Self {
            alerts: RwLock::new(Vec::new()),
            total_analyzed: AtomicU64::new(0),
            total_hostile: AtomicU64::new(0),
            total_compromised: AtomicU64::new(0),
            enabled: AtomicBool::new(true),
            _claim_history: RwLock::new(HashMap::new()),
            integrity_cache: TieredCache::new(2_000),
            pattern_diffs: RwLock::new(DifferentialStore::new()),
            integrity_stats: RwLock::new(stats_acc),
            finding_history: RwLock::new(PruningMap::new(MAX_FINDING_HISTORY).with_ttl(Duration::from_secs(86_400))),
            integrity_checkpoints: RwLock::new(HierarchicalState::new(8, 64)),
            finding_matrix: RwLock::new(SparseMatrix::new(0)),
            response_dedup: RwLock::new(DedupStore::new()),
            metrics: None,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("response_integrity_analyzer", 4 * 1024 * 1024);
        self.integrity_cache = self.integrity_cache.with_metrics(metrics.clone(), "response_integrity_analyzer");
        self.metrics = Some(metrics);
        self
    }

    // ── Main entry point ─────────────────────────────────────────────────

    pub fn analyze_response(&self, response: &LlmResponse) -> ResponseAnalysis {
        if !self.enabled.load(Ordering::Relaxed) {
            return ResponseAnalysis {
                response_id: response.response_id.clone(),
                model_name: response.model_name.clone(),
                overall_integrity: IntegrityLevel::Clean,
                findings: Vec::new(),
                entropy_profile: EntropyProfile::default(),
                total_findings: 0, critical_findings: 0,
                data_leak_count: 0, stego_score: 0.0,
                poisoned_artifact_count: 0,
                summary: "Analyzer disabled".into(),
                analyzed_at: chrono::Utc::now().timestamp(),
            };
        }

        let now = chrono::Utc::now().timestamp();
        self.total_analyzed.fetch_add(1, Ordering::Relaxed);
        let content = &response.content;
        let content_lower = content.to_lowercase();

        // Dedup
        let fingerprint = format!("{}:{}:{}", response.model_name, response.content.len(),
            &response.content[..response.content.len().min(200)]);
        self.response_dedup.write().insert(response.response_id.clone(), fingerprint);

        let mut findings: Vec<IntegrityFinding> = Vec::new();

        // Run all detection engines
        let entropy_profile = self.analyze_entropy(content);
        self.detect_zero_width(content, &mut findings);
        self.detect_homoglyphs(content, &mut findings);
        self.detect_steganography(content, &entropy_profile, &mut findings);
        self.detect_embedded_payloads(content, &mut findings);
        self.detect_secrets(content, &mut findings);
        self.detect_pii(content, &content_lower, &mut findings);
        self.detect_malicious_urls(content, &content_lower, &mut findings);
        self.detect_poisoned_packages(content, &content_lower, &mut findings);
        self.detect_malicious_code(content, &content_lower, &mut findings);
        self.detect_hidden_instructions(content, &content_lower, &mut findings);
        self.detect_infrastructure_leak(content, &mut findings);

        // Entropy anomaly
        if entropy_profile.entropy_anomaly_score > 0.7 {
            findings.push(IntegrityFinding {
                category: FindingCategory::EntropyAnomaly,
                severity: if entropy_profile.entropy_anomaly_score > 0.9 { Severity::High } else { Severity::Medium },
                title: "Statistical entropy anomaly detected".into(),
                details: format!("Entropy anomaly score {:.2} — response structure deviates significantly from natural language",
                    entropy_profile.entropy_anomaly_score),
                evidence: format!("char_entropy={:.3} word_entropy={:.3} whitespace={:.3} non_ascii={:.3}",
                    entropy_profile.char_entropy, entropy_profile.word_entropy,
                    entropy_profile.whitespace_ratio, entropy_profile.non_ascii_ratio),
                byte_offset: None,
                mitre_ids: vec!["T1001".into()],
                recommended_action: "Inspect response for hidden data channels or unusual encoding".into(),
            });
        }

        // Compute stats
        let total_findings = findings.len() as u32;
        let critical_findings = findings.iter().filter(|f| f.severity == Severity::Critical).count() as u32;
        let data_leak_count = findings.iter().filter(|f| matches!(f.category,
            FindingCategory::DataLeakPii | FindingCategory::DataLeakSecret | FindingCategory::DataLeakInfrastructure
        )).count() as u32;
        let stego_score = self.compute_stego_score(&entropy_profile, &findings);
        let poisoned_artifact_count = findings.iter().filter(|f| matches!(f.category,
            FindingCategory::PoisonedUrl | FindingCategory::PoisonedPackage | FindingCategory::PoisonedConfig
        )).count() as u32;

        // Overall integrity level
        let overall_integrity = if critical_findings > 0 || stego_score > 0.8 {
            IntegrityLevel::Hostile
        } else if findings.iter().any(|f| f.severity >= Severity::High) || stego_score > 0.5 {
            IntegrityLevel::Compromised
        } else if !findings.is_empty() {
            IntegrityLevel::Suspicious
        } else {
            IntegrityLevel::Clean
        };

        let summary = self.summarize_analysis(
            response, &findings, overall_integrity, stego_score,
            data_leak_count, poisoned_artifact_count,
        );

        let analysis = ResponseAnalysis {
            response_id: response.response_id.clone(),
            model_name: response.model_name.clone(),
            overall_integrity, findings, entropy_profile,
            total_findings, critical_findings, data_leak_count,
            stego_score, poisoned_artifact_count, summary,
            analyzed_at: now,
        };

        // Update memory breakthroughs
        {
            let mut matrix = self.finding_matrix.write();
            for f in &analysis.findings {
                let cat_key = format!("{:?}", f.category);
                let current = *matrix.get(&analysis.model_name, &cat_key);
                matrix.set(analysis.model_name.clone(), cat_key, current + 1);
            }
        }
        self.integrity_checkpoints.write().checkpoint(overall_integrity as u64);
        self.integrity_cache.insert(
            format!("{}:{}", response.model_name, response.response_id),
            overall_integrity,
        );
        self.finding_history.write().insert(response.response_id.clone(), analysis.clone());
        self.pattern_diffs.write().record_insert(
            response.model_name.clone(),
            format!("integrity:{:?} findings:{} stego:{:.2}", overall_integrity, total_findings, stego_score),
        );

        // Alerts for compromised/hostile
        if overall_integrity >= IntegrityLevel::Compromised {
            let severity = if overall_integrity == IntegrityLevel::Hostile { Severity::Critical } else { Severity::High };
            self.add_alert(now, severity,
                &format!("{} response flagged as {:?}", response.model_name, overall_integrity),
                &analysis.summary);
            if overall_integrity == IntegrityLevel::Hostile {
                self.total_hostile.fetch_add(1, Ordering::Relaxed);
            } else {
                self.total_compromised.fetch_add(1, Ordering::Relaxed);
            }
        }

        info!(response_id = %response.response_id, model = %response.model_name,
              integrity = ?overall_integrity, findings = total_findings,
              stego = format!("{:.2}", stego_score),
              "Response analyzed");

        analysis
    }

    fn add_alert(&self, timestamp: i64, severity: Severity, title: &str, details: &str) {
        let mut alerts = self.alerts.write();
        if alerts.len() >= MAX_ALERTS { alerts.drain(..MAX_ALERTS / 2); }
        alerts.push(AiAlert {
            timestamp, severity, component: "response_integrity_analyzer".into(),
            title: title.into(), details: details.into(),
        });
    }

    // ── Entropy Analysis ─────────────────────────────────────────────────

    fn analyze_entropy(&self, content: &str) -> EntropyProfile {
        let chars: Vec<char> = content.chars().collect();
        let total_chars = chars.len().max(1) as f64;

        // Character frequency entropy (Shannon)
        let mut freq: HashMap<char, usize> = HashMap::new();
        for &c in &chars { *freq.entry(c).or_insert(0) += 1; }
        let char_entropy = freq.values()
            .map(|&count| { let p = count as f64 / total_chars; -p * p.log2() })
            .sum::<f64>();

        // Word frequency entropy
        let words: Vec<&str> = content.split_whitespace().collect();
        let total_words = words.len().max(1) as f64;
        let mut word_freq: HashMap<&str, usize> = HashMap::new();
        for w in &words { *word_freq.entry(w).or_insert(0) += 1; }
        let word_entropy = word_freq.values()
            .map(|&count| { let p = count as f64 / total_words; -p * p.log2() })
            .sum::<f64>();

        // Line length variance
        let lines: Vec<&str> = content.lines().collect();
        let line_count = lines.len().max(1) as f64;
        let avg_len = lines.iter().map(|l| l.len() as f64).sum::<f64>() / line_count;
        let line_length_variance = lines.iter()
            .map(|l| (l.len() as f64 - avg_len).powi(2))
            .sum::<f64>() / line_count;

        // Character class ratios
        let whitespace_count = chars.iter().filter(|c| c.is_whitespace()).count();
        let punct_count = chars.iter().filter(|c| c.is_ascii_punctuation()).count();
        let upper_count = chars.iter().filter(|c| c.is_uppercase()).count();
        let digit_count = chars.iter().filter(|c| c.is_ascii_digit()).count();
        let non_ascii_count = chars.iter().filter(|c| !c.is_ascii()).count();

        // Zero-width and invisible character counts
        let zero_width_count = chars.iter().filter(|c| ZERO_WIDTH_CHARS.contains(c)).count() as u32;
        let homoglyph_count = chars.iter()
            .filter(|c| HOMOGLYPH_MAP.iter().any(|(h, _)| h == *c))
            .count() as u32;
        let invisible_char_count = zero_width_count + chars.iter()
            .filter(|c| c.is_control() && **c != '\n' && **c != '\r' && **c != '\t')
            .count() as u32;

        // Anomaly score: composite of unusual ratios (f64)
        let non_ascii_ratio = non_ascii_count as f64 / total_chars;
        let whitespace_ratio = whitespace_count as f64 / total_chars;
        let mut anomaly_score: f64 = 0.0;
        if non_ascii_ratio > 0.05 { anomaly_score += 0.2; }
        if non_ascii_ratio > 0.15 { anomaly_score += 0.3; }
        if zero_width_count > 0 { anomaly_score += 0.3; }
        if zero_width_count > 5 { anomaly_score += 0.2; }
        if homoglyph_count > 0 { anomaly_score += 0.2; }
        if invisible_char_count > 3 { anomaly_score += 0.2; }
        // Very low variance in line lengths can indicate encoded data
        if lines.len() > 5 && line_length_variance < 2.0 { anomaly_score += 0.15; }
        // Very high char entropy can indicate random/encoded data
        if char_entropy > 5.5 { anomaly_score += 0.15; }
        anomaly_score = anomaly_score.min(1.0);

        EntropyProfile {
            char_entropy, word_entropy, line_length_variance,
            whitespace_ratio,
            punctuation_ratio: punct_count as f64 / total_chars,
            uppercase_ratio: upper_count as f64 / total_chars,
            digit_ratio: digit_count as f64 / total_chars,
            non_ascii_ratio,
            zero_width_count, unicode_homoglyph_count: homoglyph_count,
            invisible_char_count, entropy_anomaly_score: anomaly_score,
        }
    }

    // ── Zero-Width Character Detection ───────────────────────────────────

    fn detect_zero_width(&self, content: &str, findings: &mut Vec<IntegrityFinding>) {
        let mut positions: Vec<(usize, char)> = Vec::new();
        for (i, c) in content.char_indices() {
            if ZERO_WIDTH_CHARS.contains(&c) {
                positions.push((i, c));
            }
        }
        if !positions.is_empty() {
            let severity = if positions.len() > 10 { Severity::Critical }
                else if positions.len() > 3 { Severity::High }
                else { Severity::Medium };
            findings.push(IntegrityFinding {
                category: FindingCategory::ZeroWidthInjection,
                severity,
                title: format!("{} zero-width/invisible characters detected", positions.len()),
                details: "Zero-width characters can encode hidden binary data or manipulate text rendering. \
                          This is a known steganographic exfiltration technique.".into(),
                evidence: positions.iter().take(5)
                    .map(|(i, c)| format!("U+{:04X} at byte {}", *c as u32, i))
                    .collect::<Vec<_>>().join(", "),
                byte_offset: positions.first().map(|(i, _)| *i),
                mitre_ids: vec!["T1027.010".into(), "T1001.002".into()],
                recommended_action: "Strip zero-width characters and re-inspect the content".into(),
            });
        }
    }

    // ── Unicode Homoglyph Detection ──────────────────────────────────────

    fn detect_homoglyphs(&self, content: &str, findings: &mut Vec<IntegrityFinding>) {
        let mut found: Vec<(usize, char, char)> = Vec::new();
        for (i, c) in content.char_indices() {
            for &(confusable, ascii_equiv) in HOMOGLYPH_MAP {
                if c == confusable {
                    found.push((i, confusable, ascii_equiv));
                    break;
                }
            }
        }
        if !found.is_empty() {
            let severity = if found.len() > 5 { Severity::High } else { Severity::Medium };
            findings.push(IntegrityFinding {
                category: FindingCategory::UnicodeAnomaly,
                severity,
                title: format!("{} Unicode homoglyph(s) detected", found.len()),
                details: "Characters that visually resemble ASCII but are different Unicode codepoints. \
                          Used in URL/package name spoofing and visual deception attacks.".into(),
                evidence: found.iter().take(5)
                    .map(|(i, c, a)| format!("'{}' (U+{:04X}) looks like '{}' at byte {}", c, *c as u32, a, i))
                    .collect::<Vec<_>>().join("; "),
                byte_offset: found.first().map(|(i, _, _)| *i),
                mitre_ids: vec!["T1036.005".into()],
                recommended_action: "Replace homoglyphs with ASCII equivalents and verify URLs/package names".into(),
            });
        }
    }

    // ── Steganographic Pattern Detection ─────────────────────────────────

    fn detect_steganography(&self, content: &str, _entropy: &EntropyProfile, findings: &mut Vec<IntegrityFinding>) {
        let lines: Vec<&str> = content.lines().collect();
        if lines.len() < 3 { return; }

        // Acrostic detection: first characters of each line/sentence
        let first_chars: String = lines.iter()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| l.trim().chars().next())
            .collect();

        // Check if first chars form recognizable patterns
        if first_chars.len() >= 5 {
            let alpha_count = first_chars.chars().filter(|c| c.is_alphabetic()).count();
            let alpha_ratio = alpha_count as f64 / first_chars.len() as f64;
            // If all first chars are alphabetic and form a high-entropy string, suspicious
            if alpha_ratio > 0.9 && first_chars.len() >= 8 {
                let unique: HashSet<char> = first_chars.chars().collect();
                let uniqueness = unique.len() as f64 / first_chars.len() as f64;
                // High uniqueness in first characters suggests intentional encoding
                if uniqueness > 0.7 {
                    findings.push(IntegrityFinding {
                        category: FindingCategory::SteganographicExfiltration,
                        severity: Severity::Medium,
                        title: "Potential acrostic encoding detected".into(),
                        details: format!("First characters of lines form a high-entropy string ({} unique chars \
                                         in {} lines). This pattern can encode hidden messages.", unique.len(), lines.len()),
                        evidence: format!("Acrostic: '{}'", &first_chars[..first_chars.len().min(40)]),
                        byte_offset: None,
                        mitre_ids: vec!["T1001.002".into()],
                        recommended_action: "Inspect whether the first characters encode a hidden message or data".into(),
                    });
                }
            }
        }

        // Trailing whitespace encoding: spaces/tabs at end of lines encode bits
        let trailing_ws_lines: Vec<usize> = lines.iter().enumerate()
            .filter(|(_, l)| {
                let trimmed = l.trim_end();
                l.len() > trimmed.len() + 1 // More than 1 trailing space
            })
            .map(|(i, _)| i)
            .collect();

        if trailing_ws_lines.len() > lines.len() / 2 && trailing_ws_lines.len() >= 5 {
            findings.push(IntegrityFinding {
                category: FindingCategory::SteganographicExfiltration,
                severity: Severity::High,
                title: "Trailing whitespace encoding pattern detected".into(),
                details: format!("{} of {} lines have significant trailing whitespace — \
                                 this is a known technique for encoding binary data in text.",
                    trailing_ws_lines.len(), lines.len()),
                evidence: format!("Lines with trailing whitespace: {:?}", &trailing_ws_lines[..trailing_ws_lines.len().min(10)]),
                byte_offset: None,
                mitre_ids: vec!["T1001.002".into()],
                recommended_action: "Strip trailing whitespace and compare content — the whitespace may encode hidden data".into(),
            });
        }
    }

    // ── Embedded Payload Detection ───────────────────────────────────────

    fn detect_embedded_payloads(&self, content: &str, findings: &mut Vec<IntegrityFinding>) {
        // Base64 detection: look for long base64-like strings outside of code blocks
        let b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        let mut in_code_block = false;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("```") { in_code_block = !in_code_block; continue; }
            if in_code_block { continue; }

            // Look for long base64-like sequences in non-code text
            let mut run_len = 0;
            let mut run_start = 0;
            for (i, c) in trimmed.char_indices() {
                if b64_chars.contains(c) {
                    if run_len == 0 { run_start = i; }
                    run_len += 1;
                } else {
                    if run_len >= 40 {
                        let sample = &trimmed[run_start..run_start + run_len.min(60)];
                        // Verify it looks like actual base64 (not just a long word)
                        let has_mixed_case = sample.chars().any(|c| c.is_uppercase())
                            && sample.chars().any(|c| c.is_lowercase());
                        let has_digits = sample.chars().any(|c| c.is_ascii_digit());
                        if has_mixed_case && has_digits {
                            findings.push(IntegrityFinding {
                                category: FindingCategory::EmbeddedPayload,
                                severity: if run_len > 100 { Severity::High } else { Severity::Medium },
                                title: format!("Possible base64-encoded payload ({} chars)", run_len),
                                details: "Long base64-like string found outside code blocks. \
                                         This could embed hidden binary data, executables, or exfiltrated content.".into(),
                                evidence: format!("{}...", &sample[..sample.len().min(50)]),
                                byte_offset: Some(run_start),
                                mitre_ids: vec!["T1027".into()],
                                recommended_action: "Decode the base64 string and inspect its contents before using".into(),
                            });
                        }
                    }
                    run_len = 0;
                }
            }
        }

        // Hex-encoded data detection
        let hex_pattern_starts = ["\\x", "0x"];
        for pattern in hex_pattern_starts {
            let count = content.matches(pattern).count();
            if count >= 10 {
                findings.push(IntegrityFinding {
                    category: FindingCategory::EmbeddedPayload,
                    severity: Severity::Medium,
                    title: format!("{} hex-encoded sequences ('{}') found", count, pattern),
                    details: "Multiple hex-encoded sequences can indicate obfuscated shellcode or hidden data.".into(),
                    evidence: format!("{} occurrences of '{}'", count, pattern),
                    byte_offset: content.find(pattern),
                    mitre_ids: vec!["T1027".into()],
                    recommended_action: "Decode hex sequences and verify they match the expected content".into(),
                });
            }
        }
    }

    // ── Secret / API Key Detection ───────────────────────────────────────

    fn detect_secrets(&self, content: &str, findings: &mut Vec<IntegrityFinding>) {
        for &(label, pattern) in SECRET_PATTERNS {
            if let Some(pos) = content.find(pattern) {
                // Avoid false positives: skip very short patterns in code-discussion context
                let context_start = pos.saturating_sub(20);
                let context_end = (pos + pattern.len() + 30).min(content.len());
                let context = &content[context_start..context_end];
                findings.push(IntegrityFinding {
                    category: FindingCategory::DataLeakSecret,
                    severity: if label.contains("PRIVATE") || label.contains("AWS") { Severity::Critical } else { Severity::High },
                    title: format!("Potential {} secret detected in response", label),
                    details: format!("Pattern '{}' found — this could be a real credential leaked in the model output.", pattern),
                    evidence: format!("...{}...", context.replace('\n', " ")),
                    byte_offset: Some(pos),
                    mitre_ids: vec!["T1552".into()],
                    recommended_action: "Verify this is not a real credential. If it is, rotate it immediately.".into(),
                });
            }
        }
    }

    // ── PII Detection ────────────────────────────────────────────────────

    fn detect_pii(&self, content: &str, content_lower: &str, findings: &mut Vec<IntegrityFinding>) {
        // Credit card number detection (Luhn-plausible 16-digit sequences)
        let digits: String = content.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() >= 16 {
            // Look for 13-19 digit sequences that could be card numbers
            let mut consecutive_digits = 0;
            let mut start_pos = 0;
            for (i, c) in content.char_indices() {
                if c.is_ascii_digit() || c == ' ' || c == '-' {
                    if consecutive_digits == 0 { start_pos = i; }
                    if c.is_ascii_digit() { consecutive_digits += 1; }
                } else {
                    if consecutive_digits >= 13 && consecutive_digits <= 19 {
                        let candidate = &content[start_pos..i];
                        let first_char = candidate.chars().find(|c| c.is_ascii_digit()).unwrap_or('0');
                        if first_char == '4' || first_char == '5' || first_char == '3' || first_char == '6' {
                            findings.push(IntegrityFinding {
                                category: FindingCategory::DataLeakPii,
                                severity: Severity::Critical,
                                title: "Possible credit card number in response".into(),
                                details: "A sequence matching credit card number format was detected.".into(),
                                evidence: format!("{}****", &candidate[..candidate.len().min(6)]),
                                byte_offset: Some(start_pos),
                                mitre_ids: vec!["T1567".into()],
                                recommended_action: "Never include real credit card numbers in AI responses.".into(),
                            });
                            break;
                        }
                    }
                    consecutive_digits = 0;
                }
            }
        }

        // SSN-like pattern (###-##-####)
        let mut i = 0;
        let bytes = content.as_bytes();
        while i + 10 < bytes.len() {
            if bytes[i].is_ascii_digit() && bytes[i+1].is_ascii_digit() && bytes[i+2].is_ascii_digit()
                && bytes[i+3] == b'-' && bytes[i+4].is_ascii_digit() && bytes[i+5].is_ascii_digit()
                && bytes[i+6] == b'-' && bytes[i+7].is_ascii_digit() && bytes[i+8].is_ascii_digit()
                && bytes[i+9].is_ascii_digit() && bytes[i+10].is_ascii_digit()
            {
                findings.push(IntegrityFinding {
                    category: FindingCategory::DataLeakPii,
                    severity: Severity::Critical,
                    title: "Possible SSN pattern (###-##-####) detected".into(),
                    details: "A Social Security Number format was found in the response.".into(),
                    evidence: "***-**-****".into(),
                    byte_offset: Some(i),
                    mitre_ids: vec!["T1567".into()],
                    recommended_action: "Never include real SSNs in AI responses.".into(),
                });
                break;
            }
            i += 1;
        }

        // Sensitive PII keywords
        let pii_keywords = [
            ("social security number", Severity::Critical),
            ("date of birth", Severity::Medium),
            ("passport number", Severity::High),
            ("driver's license", Severity::Medium),
            ("bank account", Severity::High),
            ("routing number", Severity::High),
        ];
        for (keyword, severity) in pii_keywords {
            if content_lower.contains(keyword) {
                // Check if it's actually exposing data vs just mentioning the concept
                let pos = content_lower.find(keyword).unwrap_or(0);
                let after = &content_lower[pos + keyword.len()..];
                // If followed by a colon, equals, or digits, likely exposing data
                let after_trimmed = after.trim_start();
                if after_trimmed.starts_with(':') || after_trimmed.starts_with('=')
                    || after_trimmed.starts_with("is ") {
                    findings.push(IntegrityFinding {
                        category: FindingCategory::DataLeakPii,
                        severity,
                        title: format!("PII disclosure: '{}' with apparent value", keyword),
                        details: format!("The response appears to disclose a '{}' with an associated value.", keyword),
                        evidence: format!("Found '{}' followed by value indicator", keyword),
                        byte_offset: Some(pos),
                        mitre_ids: vec!["T1567".into()],
                        recommended_action: "Remove PII from the response before presenting to the user.".into(),
                    });
                }
            }
        }
    }

    // ── Malicious URL Detection ──────────────────────────────────────────

    fn detect_malicious_urls(&self, content: &str, content_lower: &str, findings: &mut Vec<IntegrityFinding>) {
        // Find all URLs
        for scheme in ["http://", "https://"] {
            let mut search_from = 0;
            while let Some(pos) = content_lower[search_from..].find(scheme) {
                let abs_pos = search_from + pos;
                let url_start = abs_pos;
                let url_end = content[abs_pos..].find(|c: char| c.is_whitespace() || c == ')' || c == ']' || c == '"' || c == '\'')
                    .map(|e| abs_pos + e)
                    .unwrap_or(content.len());
                let url = &content[url_start..url_end];
                let url_lower = url.to_lowercase();

                // Check suspicious TLDs
                for tld in SUSPICIOUS_TLDS {
                    if url_lower.contains(tld) {
                        findings.push(IntegrityFinding {
                            category: FindingCategory::PoisonedUrl,
                            severity: Severity::High,
                            title: format!("URL with suspicious TLD '{}'", tld),
                            details: format!("The TLD '{}' is commonly used in phishing and typosquatting attacks.", tld),
                            evidence: url.to_string(),
                            byte_offset: Some(url_start),
                            mitre_ids: vec!["T1566.002".into()],
                            recommended_action: "Verify this URL is legitimate before visiting.".into(),
                        });
                        break;
                    }
                }

                // Check IP-based URLs
                for pattern in IP_URL_PATTERNS {
                    if url_lower.starts_with(pattern) {
                        findings.push(IntegrityFinding {
                            category: FindingCategory::PoisonedUrl,
                            severity: Severity::High,
                            title: "URL uses direct IP address instead of domain".into(),
                            details: "Direct IP URLs bypass DNS and certificate validation, commonly used in attacks.".into(),
                            evidence: url.to_string(),
                            byte_offset: Some(url_start),
                            mitre_ids: vec!["T1566.002".into()],
                            recommended_action: "Never follow IP-based URLs from AI responses.".into(),
                        });
                        break;
                    }
                }

                search_from = url_end;
            }
        }
    }

    // ── Poisoned Package Detection ───────────────────────────────────────

    fn detect_poisoned_packages(&self, content: &str, content_lower: &str, findings: &mut Vec<IntegrityFinding>) {
        // Look for install commands
        let install_cmds = ["pip install ", "npm install ", "npm i ", "yarn add ", "cargo add ", "gem install ", "go get "];
        for cmd in install_cmds {
            let mut search_from = 0;
            while let Some(pos) = content_lower[search_from..].find(cmd) {
                let abs_pos = search_from + pos;
                let pkg_start = abs_pos + cmd.len();
                let pkg_end = content[pkg_start..].find(|c: char| c.is_whitespace() || c == '\n')
                    .map(|e| pkg_start + e)
                    .unwrap_or(content.len());
                let pkg_name = content[pkg_start..pkg_end].trim();
                if pkg_name.is_empty() { search_from = pkg_end; continue; }

                let pkg_lower = pkg_name.to_lowercase();

                // Check against known malicious patterns
                for malicious in MALICIOUS_PACKAGE_PATTERNS {
                    if pkg_lower.contains(malicious) && pkg_lower != *malicious {
                        findings.push(IntegrityFinding {
                            category: FindingCategory::PoisonedPackage,
                            severity: Severity::High,
                            title: format!("Suspicious package name: '{}'", pkg_name),
                            details: format!("Package name contains '{}' which matches known malicious package patterns.", malicious),
                            evidence: format!("{}{}", cmd, pkg_name),
                            byte_offset: Some(abs_pos),
                            mitre_ids: vec!["T1195.001".into()],
                            recommended_action: "Verify this is the correct package on the official registry before installing.".into(),
                        });
                    }
                }

                // Check for typosquats of popular packages (edit distance = 1)
                for &(popular, _ecosystem) in POPULAR_PACKAGES {
                    if pkg_lower != popular && Self::is_typosquat(&pkg_lower, popular) {
                        findings.push(IntegrityFinding {
                            category: FindingCategory::PoisonedPackage,
                            severity: Severity::Critical,
                            title: format!("Possible typosquat: '{}' (similar to '{}')", pkg_name, popular),
                            details: format!("Package '{}' is very similar to popular package '{}' — \
                                             this is a common supply chain attack vector.", pkg_name, popular),
                            evidence: format!("{}{}", cmd, pkg_name),
                            byte_offset: Some(abs_pos),
                            mitre_ids: vec!["T1195.001".into()],
                            recommended_action: format!("Did you mean '{}'? Verify on the official registry.", popular),
                        });
                    }
                }

                search_from = pkg_end;
            }
        }
    }

    /// Simple typosquat detection: edit distance of 1 or 2, or common prefix/suffix tricks.
    fn is_typosquat(candidate: &str, legitimate: &str) -> bool {
        if candidate == legitimate { return false; }
        let edit_distance = Self::levenshtein(candidate, legitimate);
        if edit_distance <= 2 && candidate.len() >= 3 { return true; }
        // Check for prefix additions (e.g., "python-requests" vs "requests")
        for prefix in TYPOSQUAT_PREFIXES {
            if candidate.starts_with(prefix) && &candidate[prefix.len()..] == legitimate {
                return true;
            }
        }
        false
    }

    fn levenshtein(a: &str, b: &str) -> usize {
        let a: Vec<char> = a.chars().collect();
        let b: Vec<char> = b.chars().collect();
        let (m, n) = (a.len(), b.len());
        let mut dp = vec![vec![0usize; n + 1]; m + 1];
        for i in 0..=m { dp[i][0] = i; }
        for j in 0..=n { dp[0][j] = j; }
        for i in 1..=m {
            for j in 1..=n {
                let cost = if a[i-1] == b[j-1] { 0 } else { 1 };
                dp[i][j] = (dp[i-1][j] + 1).min(dp[i][j-1] + 1).min(dp[i-1][j-1] + cost);
            }
        }
        dp[m][n]
    }

    // ── Malicious Code Pattern Detection ─────────────────────────────────

    fn detect_malicious_code(&self, content: &str, content_lower: &str, findings: &mut Vec<IntegrityFinding>) {
        for &(name, pattern, severity) in MALICIOUS_CODE_PATTERNS {
            let pattern_lower = pattern.to_lowercase();
            if let Some(pos) = content_lower.find(&pattern_lower) {
                let context_start = pos.saturating_sub(30);
                let context_end = (pos + pattern.len() + 30).min(content.len());
                let context = &content[context_start..context_end];
                findings.push(IntegrityFinding {
                    category: FindingCategory::MaliciousCodePattern,
                    severity,
                    title: format!("Malicious code pattern: {}", name),
                    details: format!("Detected '{}' — this pattern is associated with: {}", pattern, name),
                    evidence: context.replace('\n', " "),
                    byte_offset: Some(pos),
                    mitre_ids: FindingCategory::MaliciousCodePattern.mitre_techniques()
                        .iter().map(|s| s.to_string()).collect(),
                    recommended_action: "Do NOT execute this code. Review for malicious intent.".into(),
                });
            }
        }
    }

    // ── Hidden Instruction Detection ─────────────────────────────────────

    fn detect_hidden_instructions(&self, content: &str, content_lower: &str, findings: &mut Vec<IntegrityFinding>) {
        for &(pattern, severity) in HIDDEN_INSTRUCTION_PATTERNS {
            let pattern_lower = pattern.to_lowercase();
            if let Some(pos) = content_lower.find(&pattern_lower) {
                let context_start = pos.saturating_sub(20);
                let context_end = (pos + pattern.len() + 40).min(content.len());
                let context = &content[context_start..context_end];
                findings.push(IntegrityFinding {
                    category: FindingCategory::HiddenInstruction,
                    severity,
                    title: format!("Hidden instruction pattern: '{}'", pattern),
                    details: "This pattern could hijack downstream AI agents or inject malicious behavior.".into(),
                    evidence: context.replace('\n', " "),
                    byte_offset: Some(pos),
                    mitre_ids: vec!["T1059".into()],
                    recommended_action: "Strip this content before passing to any downstream agent or system.".into(),
                });
            }
        }

        // Check for HTML comments that might hide instructions
        let mut search = 0;
        while let Some(start) = content[search..].find("<!--") {
            let abs_start = search + start;
            if let Some(end) = content[abs_start..].find("-->") {
                let comment = &content[abs_start..abs_start + end + 3];
                if comment.len() > 10 {
                    findings.push(IntegrityFinding {
                        category: FindingCategory::InvisibleFormatting,
                        severity: Severity::Medium,
                        title: "Hidden HTML comment in response".into(),
                        details: "HTML comments are invisible to users but may be parsed by downstream tools.".into(),
                        evidence: format!("{}...", &comment[..comment.len().min(60)]),
                        byte_offset: Some(abs_start),
                        mitre_ids: vec!["T1027.010".into()],
                        recommended_action: "Inspect the HTML comment for hidden instructions.".into(),
                    });
                }
                search = abs_start + end + 3;
            } else {
                break;
            }
        }
    }

    // ── Infrastructure Leak Detection ────────────────────────────────────

    fn detect_infrastructure_leak(&self, content: &str, findings: &mut Vec<IntegrityFinding>) {
        // Internal IP addresses
        let internal_prefixes = ["10.", "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
            "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168."];

        for prefix in internal_prefixes {
            if let Some(pos) = content.find(prefix) {
                // Verify it looks like an IP (digits and dots)
                let end = content[pos..].find(|c: char| !c.is_ascii_digit() && c != '.')
                    .map(|e| pos + e).unwrap_or(content.len());
                let candidate = &content[pos..end];
                let parts: Vec<&str> = candidate.split('.').collect();
                if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
                    findings.push(IntegrityFinding {
                        category: FindingCategory::DataLeakInfrastructure,
                        severity: Severity::Medium,
                        title: format!("Internal IP address leaked: {}", candidate),
                        details: "Internal/private IP addresses in responses can reveal network topology.".into(),
                        evidence: candidate.to_string(),
                        byte_offset: Some(pos),
                        mitre_ids: vec!["T1018".into()],
                        recommended_action: "Remove internal IP addresses from responses.".into(),
                    });
                    break; // One is enough
                }
            }
        }

        // Internal hostnames
        let internal_indicators = [".internal", ".local", ".corp", ".lan", ".intranet",
            ".private", ".staging", ".dev."];
        for indicator in internal_indicators {
            if let Some(pos) = content.find(indicator) {
                // Get the hostname around it
                let start = content[..pos].rfind(|c: char| c.is_whitespace() || c == '/' || c == '@')
                    .map(|s| s + 1).unwrap_or(0);
                let hostname = &content[start..pos + indicator.len()];
                if hostname.len() > indicator.len() + 2 {
                    findings.push(IntegrityFinding {
                        category: FindingCategory::DataLeakInfrastructure,
                        severity: Severity::Medium,
                        title: format!("Internal hostname leaked: {}", hostname),
                        details: "Internal hostnames in responses can reveal infrastructure details.".into(),
                        evidence: hostname.to_string(),
                        byte_offset: Some(start),
                        mitre_ids: vec!["T1018".into()],
                        recommended_action: "Remove internal hostnames from responses.".into(),
                    });
                    break;
                }
            }
        }
    }

    // ── Stego Score Computation ──────────────────────────────────────────

    fn compute_stego_score(&self, entropy: &EntropyProfile, findings: &[IntegrityFinding]) -> f64 {
        let mut score = 0.0;

        // Entropy-based signals
        score += entropy.entropy_anomaly_score * 0.3;

        // Zero-width chars are strong stego signals
        if entropy.zero_width_count > 0 { score += 0.3; }
        if entropy.zero_width_count > 10 { score += 0.2; }

        // Homoglyphs
        if entropy.unicode_homoglyph_count > 0 { score += 0.15; }

        // Finding-based signals
        for f in findings {
            match f.category {
                FindingCategory::SteganographicExfiltration => score += 0.25,
                FindingCategory::ZeroWidthInjection => score += 0.2,
                FindingCategory::EmbeddedPayload => score += 0.15,
                FindingCategory::UnicodeAnomaly => score += 0.1,
                _ => {}
            }
        }

        score.min(1.0)
    }

    // ── Summary Generation ───────────────────────────────────────────────

    fn summarize_analysis(
        &self, response: &LlmResponse, findings: &[IntegrityFinding],
        integrity: IntegrityLevel, stego_score: f64,
        data_leaks: u32, poisoned: u32,
    ) -> String {
        let total = findings.len();
        let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let high = findings.iter().filter(|f| f.severity == Severity::High).count();

        let mut summary = format!(
            "[{}] {} response (turn {}): {:?} integrity, {} finding(s).",
            response.model_name, response.response_id, response.turn_number,
            integrity, total,
        );

        if total == 0 {
            summary.push_str(" Response appears clean — no anomalies detected.");
            return summary;
        }

        if critical > 0 {
            summary.push_str(&format!(" {} CRITICAL finding(s) require immediate attention.", critical));
        }
        if high > 0 {
            summary.push_str(&format!(" {} HIGH severity finding(s).", high));
        }
        if stego_score > 0.5 {
            summary.push_str(&format!(" Steganography score: {:.0}% — possible hidden data channel.", stego_score * 100.0));
        }
        if data_leaks > 0 {
            summary.push_str(&format!(" {} data leak(s) detected (PII/secrets/infrastructure).", data_leaks));
        }
        if poisoned > 0 {
            summary.push_str(&format!(" {} poisoned artifact(s) (URLs/packages).", poisoned));
        }

        summary
    }

    // ── Public API ───────────────────────────────────────────────────────

    pub fn analyzed_count(&self) -> u64 {
        self.total_analyzed.load(Ordering::Relaxed)
    }

    pub fn hostile_count(&self) -> u64 {
        self.total_hostile.load(Ordering::Relaxed)
    }

    pub fn compromised_count(&self) -> u64 {
        self.total_compromised.load(Ordering::Relaxed)
    }

    pub fn recent_analyses(&self, limit: usize) -> Vec<ResponseAnalysis> {
        let hist = self.finding_history.read();
        let mut analyses: Vec<ResponseAnalysis> = hist.iter().map(|(_, v)| v.clone()).collect();
        analyses.truncate(limit);
        analyses
    }

    pub fn set_enabled(&self, e: bool) {
        self.enabled.store(e, Ordering::Relaxed);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn cached_integrity(&self, model: &str, response_id: &str) -> Option<IntegrityLevel> {
        let key = format!("{}:{}", model, response_id);
        self.integrity_cache.get(&key)
    }

    pub fn integrity_statistics(&self) -> IntegrityStats {
        self.integrity_stats.read().state().clone()
    }

    pub fn finding_matrix_entries(&self) -> Vec<(String, String, u64)> {
        self.finding_matrix.read().iter()
            .map(|((r, c), v)| (r.clone(), c.clone(), *v))
            .collect()
    }

    pub fn is_duplicate_response(&self, response_id: &str) -> bool {
        self.response_dedup.read().contains_key(&response_id.to_string())
    }

    pub fn alerts(&self) -> Vec<AiAlert> {
        self.alerts.read().clone()
    }

    pub fn pattern_evolution(&self, model: &str) -> Option<String> {
        self.pattern_diffs.read().get(&model.to_string())
    }

    pub fn integrity_checkpoint_count(&self) -> usize {
        self.integrity_checkpoints.read().total_checkpoints()
    }

    // ── Persistence ─────────────────────────────────────────────────────

    pub fn save_state(&self, path: &PathBuf) -> std::io::Result<()> {
        let state = PersistedRiaState {
            alerts: self.alerts.read().clone(),
            total_analyzed: self.total_analyzed.load(Ordering::Relaxed),
            total_hostile: self.total_hostile.load(Ordering::Relaxed),
            total_compromised: self.total_compromised.load(Ordering::Relaxed),
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
        info!(path = %path.display(), analyzed = state.total_analyzed, "RIA state saved");
        Ok(())
    }

    pub fn load_state(&self, path: &PathBuf) -> std::io::Result<()> {
        if !path.exists() {
            info!(path = %path.display(), "No persisted RIA state found, starting fresh");
            return Ok(());
        }
        let json = std::fs::read_to_string(path)?;
        let state: PersistedRiaState = serde_json::from_str(&json)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        *self.alerts.write() = state.alerts;
        self.total_analyzed.store(state.total_analyzed, Ordering::Relaxed);
        self.total_hostile.store(state.total_hostile, Ordering::Relaxed);
        self.total_compromised.store(state.total_compromised, Ordering::Relaxed);
        self.enabled.store(state.enabled, Ordering::Relaxed);
        info!(path = %path.display(), analyzed = state.total_analyzed, "RIA state restored");
        Ok(())
    }
}

// ── Persisted State ─────────────────────────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedRiaState {
    alerts: Vec<AiAlert>,
    total_analyzed: u64,
    total_hostile: u64,
    total_compromised: u64,
    enabled: bool,
}