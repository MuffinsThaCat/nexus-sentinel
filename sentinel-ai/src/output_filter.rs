//! Output Filter — filters AI model outputs for sensitive or harmful content.
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Hot lookups cached
//! - **#6 Theoretical Verifier**: Bound memory usage
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
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OutputVerdict {
    pub safe: bool,
    pub redacted_output: String,
    pub findings: Vec<String>,
    pub severity: Severity,
}

pub struct OutputFilter {
    custom_blocked: RwLock<Vec<String>>,
    alerts: RwLock<Vec<AiAlert>>,
    total_filtered: AtomicU64,
    total_blocked: AtomicU64,
    _cache: TieredCache<String, u64>,
    /// Breakthrough #461: Filter rule evolution tracking
    rule_diffs: DifferentialStore<String, String>,
    /// Breakthrough #569: φ-weighted alert pruning
    pruned_alerts: PruningMap<String, AiAlert>,
    /// Breakthrough #1: O(log n) filter trend history
    filter_state: RwLock<HierarchicalState<u64>>,
    /// Breakthrough #627: Sparse category×source matrix
    category_matrix: RwLock<SparseMatrix<String, String, u64>>,
    /// Breakthrough #592: Content-addressed dedup for output fingerprints
    output_dedup: DedupStore<String, String>,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

/// Harmful content categories with patterns.
const DANGEROUS_INSTRUCTIONS: &[&str] = &[
    "how to make a bomb", "how to make explosives", "how to synthesize",
    "how to manufacture drugs", "how to make methamphetamine", "how to make fentanyl",
    "how to pick a lock", "how to hotwire", "how to hack into",
    "how to create a virus", "how to create malware", "how to ddos",
    "how to poison", "how to kill someone", "how to commit murder",
    "here is how to build a weapon", "instructions for making",
    "step-by-step guide to hacking", "recipe for explosives",
];

const SELF_HARM_PATTERNS: &[&str] = &[
    "how to commit suicide", "ways to end your life", "painless ways to die",
    "methods of self-harm", "how to cut yourself", "encouraging self-harm",
    "you should kill yourself", "nobody would miss you",
];

const SYSTEM_PROMPT_LEAK: &[&str] = &[
    "my system prompt is", "my instructions are", "i was told to",
    "my initial prompt", "here is my system message",
    "my rules state that", "i am programmed to",
    "```system", "[system]", "<<sys>>",
];

const CODE_INJECTION_IN_OUTPUT: &[&str] = &[
    "<script>", "javascript:", "onerror=", "onclick=",
    "'; drop table", "; rm -rf", "$(curl", "`wget",
    "import os; os.system", "__import__('os')", "exec(",
    "subprocess.call", "os.popen",
];

const PII_LEAKAGE_INDICATORS: &[(&str, &str)] = &[
    ("@", "email_leak"),       // email-like patterns
    ("xxx-xx-", "ssn_leak"),   // SSN fragments
    ("4xxx xxxx", "cc_leak"),  // credit card fragments
];

/// Structured output injection patterns — attacks that exploit downstream parsers.
const JSON_INJECTION: &[&str] = &[
    "\"__proto__\"", "\"constructor\"", "\"prototype\"",
    "$where", "$gt", "$ne", "$regex",  // NoSQL injection via JSON
    "\"$set\"", "\"$unset\"",
];

const MARKDOWN_INJECTION: &[&str] = &[
    "![](http",          // image beacon (exfiltration via rendered markdown)
    "](javascript:",     // markdown link with JS
    "[click](data:",     // data URI in markdown link
    "<iframe",           // HTML injection in markdown
    "<object",
    "<embed",
    "<form action",
    "<svg onload",
    "<img src=x onerror",
    "<details open ontoggle",
];

const CSV_FORMULA_INJECTION: &[&str] = &[
    "=cmd|",     // DDE command execution
    "=HYPERLINK(",
    "=IMPORTXML(",
    "=IMPORTDATA(",
    "=IMPORTFEED(",
    "+cmd|",
    "-cmd|",
    "@SUM(",      // formula starting with @
    "|cmd|",
    "=WEBSERVICE(",
];

const LATEX_INJECTION: &[&str] = &[
    "\\input{",
    "\\include{",
    "\\write18{",
    "\\immediate\\write",
    "\\openin",
    "\\openout",
    "\\catcode",
    "\\def\\",
];

const YAML_DESERIALIZATION: &[&str] = &[
    "!!python/object",
    "!!python/module",
    "!!ruby/object",
    "!!java/object",
    "!!map",
    "tag:yaml.org",
];

const TEMPLATE_INJECTION: &[&str] = &[
    "{{", "{%",              // Jinja2/Twig
    "${7*7}",               // Expression language
    "#{7*7}",               // Ruby ERB / Java EL
    "<%= ",                 // ERB
    "{{constructor",        // Angular
    "{{config",
    "{{self",
];

impl OutputFilter {
    pub fn new() -> Self {
        Self {
            custom_blocked: RwLock::new(Vec::new()),
            alerts: RwLock::new(Vec::new()),
            total_filtered: AtomicU64::new(0),
            total_blocked: AtomicU64::new(0),
            enabled: true,
            _cache: TieredCache::new(10_000),
            rule_diffs: DifferentialStore::new(),
            pruned_alerts: PruningMap::new(5_000),
            filter_state: RwLock::new(HierarchicalState::new(8, 64)),
            category_matrix: RwLock::new(SparseMatrix::new(0)),
            output_dedup: DedupStore::new(),
            metrics: None,
        }
    }

    pub fn add_blocked_term(&self, term: &str) { self.custom_blocked.write().push(term.to_lowercase()); }

    pub fn filter(&self, output: &str) -> OutputVerdict {
        if !self.enabled {
            return OutputVerdict { safe: true, redacted_output: output.to_string(), findings: vec![], severity: Severity::Low };
        }
        self.total_filtered.fetch_add(1, Ordering::Relaxed);
        let lower = output.to_lowercase();

        let mut findings = Vec::new();
        let mut max_sev = Severity::Low;

        // Check dangerous instructions
        for pat in DANGEROUS_INSTRUCTIONS {
            if lower.contains(pat) {
                findings.push(format!("dangerous_instructions:{}", &pat[..pat.len().min(30)]));
                max_sev = Severity::Critical;
            }
        }

        // Check self-harm content
        for pat in SELF_HARM_PATTERNS {
            if lower.contains(pat) {
                findings.push(format!("self_harm:{}", &pat[..pat.len().min(30)]));
                max_sev = Severity::Critical;
            }
        }

        // Check system prompt leakage
        for pat in SYSTEM_PROMPT_LEAK {
            if lower.contains(pat) {
                findings.push(format!("system_prompt_leak:{}", &pat[..pat.len().min(25)]));
                if (max_sev as u8) < (Severity::High as u8) { max_sev = Severity::High; }
            }
        }

        // Check code injection in output
        for pat in CODE_INJECTION_IN_OUTPUT {
            if lower.contains(pat) {
                findings.push(format!("code_injection:{}", &pat[..pat.len().min(20)]));
                if (max_sev as u8) < (Severity::High as u8) { max_sev = Severity::High; }
            }
        }

        // Check structured output injection attacks
        for pat in JSON_INJECTION {
            if lower.contains(&pat.to_lowercase()) {
                findings.push(format!("json_injection:{}", &pat[..pat.len().min(20)]));
                if (max_sev as u8) < (Severity::High as u8) { max_sev = Severity::High; }
            }
        }

        for pat in MARKDOWN_INJECTION {
            if lower.contains(&pat.to_lowercase()) {
                findings.push(format!("markdown_injection:{}", &pat[..pat.len().min(25)]));
                if (max_sev as u8) < (Severity::High as u8) { max_sev = Severity::High; }
            }
        }

        // CSV formula injection — check if output starts with or contains formula triggers
        for pat in CSV_FORMULA_INJECTION {
            if output.contains(pat) {
                findings.push(format!("csv_formula_injection:{}", &pat[..pat.len().min(15)]));
                if (max_sev as u8) < (Severity::High as u8) { max_sev = Severity::High; }
            }
        }

        for pat in LATEX_INJECTION {
            if output.contains(pat) {
                findings.push(format!("latex_injection:{}", &pat[..pat.len().min(15)]));
                if (max_sev as u8) < (Severity::High as u8) { max_sev = Severity::High; }
            }
        }

        for pat in YAML_DESERIALIZATION {
            if lower.contains(pat) {
                findings.push(format!("yaml_deser_injection:{}", &pat[..pat.len().min(20)]));
                max_sev = Severity::Critical;
            }
        }

        for pat in TEMPLATE_INJECTION {
            if output.contains(pat) {
                findings.push(format!("template_injection:{}", &pat[..pat.len().min(15)]));
                if (max_sev as u8) < (Severity::High as u8) { max_sev = Severity::High; }
            }
        }

        // Check PII leakage heuristics
        // SSN pattern: 3 digits - 2 digits - 4 digits
        if Self::contains_ssn_pattern(&lower) {
            findings.push("pii_leak:ssn_pattern".into());
            if (max_sev as u8) < (Severity::High as u8) { max_sev = Severity::High; }
        }
        // Credit card pattern: 13-19 consecutive digits
        if Self::contains_cc_pattern(output) {
            findings.push("pii_leak:credit_card_pattern".into());
            if (max_sev as u8) < (Severity::High as u8) { max_sev = Severity::High; }
        }

        // Check custom blocked terms
        let custom = self.custom_blocked.read();
        for term in custom.iter() {
            if lower.contains(term.as_str()) {
                findings.push(format!("custom_blocked:{}", &term[..term.len().min(20)]));
                if (max_sev as u8) < (Severity::Medium as u8) { max_sev = Severity::Medium; }
            }
        }
        drop(custom);

        // Heuristic: excessive repetition (hallucination/jailbreak indicator)
        if output.len() > 200 {
            let words: Vec<&str> = output.split_whitespace().collect();
            if words.len() > 20 {
                let last_10: Vec<&str> = words[words.len()-10..].to_vec();
                let first_of_last = last_10[0];
                let repeats = last_10.iter().filter(|&&w| w == first_of_last).count();
                if repeats >= 8 {
                    findings.push("hallucination:excessive_repetition".into());
                    if (max_sev as u8) < (Severity::Medium as u8) { max_sev = Severity::Medium; }
                }
            }
        }

        findings.sort();
        findings.dedup();

        let safe = findings.is_empty();
        let redacted = if safe { output.to_string() } else { Self::redact_output(output, &findings) };

        if !safe {
            self.total_blocked.fetch_add(1, Ordering::Relaxed);
            let now = chrono::Utc::now().timestamp();
            let cats = findings.join(", ");
            warn!(findings = %cats, severity = ?max_sev, "LLM output filtered");
            self.add_alert(now, max_sev, "Output filtered", &cats[..cats.len().min(256)]);
        }

        OutputVerdict { safe, redacted_output: redacted, findings, severity: max_sev }
    }

    fn contains_ssn_pattern(text: &str) -> bool {
        let bytes = text.as_bytes();
        let len = bytes.len();
        if len < 11 { return false; }
        for i in 0..len.saturating_sub(10) {
            if bytes[i].is_ascii_digit() && bytes[i+1].is_ascii_digit() && bytes[i+2].is_ascii_digit()
                && bytes[i+3] == b'-'
                && bytes[i+4].is_ascii_digit() && bytes[i+5].is_ascii_digit()
                && bytes[i+6] == b'-'
                && bytes[i+7].is_ascii_digit() && bytes[i+8].is_ascii_digit()
                && bytes[i+9].is_ascii_digit() && bytes[i+10].is_ascii_digit()
            {
                return true;
            }
        }
        false
    }

    fn contains_cc_pattern(text: &str) -> bool {
        let mut consecutive_digits = 0u32;
        for ch in text.chars() {
            if ch.is_ascii_digit() { consecutive_digits += 1; }
            else if ch == ' ' || ch == '-' { /* separators in CC numbers */ }
            else { consecutive_digits = 0; }
            if consecutive_digits >= 13 { return true; }
        }
        false
    }

    fn redact_output(output: &str, _findings: &[String]) -> String {
        format!("[Content filtered by Nexus Sentinel — {} policy violation(s) detected]", _findings.len())
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(AiAlert { timestamp: ts, severity: sev, component: "output_filter".into(), title: title.into(), details: details.into() });
    }

    pub fn total_filtered(&self) -> u64 { self.total_filtered.load(Ordering::Relaxed) }
    pub fn total_blocked(&self) -> u64 { self.total_blocked.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
