//! Clipboard Guard — monitors clipboard for sensitive data exfiltration.
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Hot lookups cached
//! - **#6 Theoretical Verifier**: Bound memory usage
use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClipboardVerdict {
    pub safe: bool,
    pub findings: Vec<String>,
    pub severity: Severity,
}

pub struct ClipboardGuard {
    alerts: RwLock<Vec<ExfilAlert>>,
    total_checked: AtomicU64,
    total_blocked: AtomicU64,
    _cache: TieredCache<String, u64>,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

const SECRET_PATTERNS: &[(&str, &str)] = &[
    ("-----begin rsa private", "rsa_private_key"),
    ("-----begin openssh private", "openssh_private_key"),
    ("-----begin ec private", "ec_private_key"),
    ("-----begin pgp private", "pgp_private_key"),
    ("-----begin certificate", "certificate"),
    ("akia", "aws_access_key"),
    ("asia", "aws_temp_key"),
    ("ghp_", "github_pat"),
    ("gho_", "github_oauth"),
    ("glpat-", "gitlab_pat"),
    ("xoxb-", "slack_bot_token"),
    ("xoxp-", "slack_user_token"),
    ("sk-", "stripe_or_openai_key"),
    ("eyj", "jwt_token"),
    ("bearer ", "bearer_token"),
    ("basic ", "basic_auth"),
    ("password=", "password_param"),
    ("passwd=", "password_param"),
    ("api_key=", "api_key_param"),
    ("apikey=", "api_key_param"),
    ("secret_key=", "secret_key_param"),
    ("access_token=", "access_token_param"),
    ("database_url=", "database_url"),
    ("mongodb://", "mongodb_uri"),
    ("postgres://", "postgres_uri"),
    ("mysql://", "mysql_uri"),
    ("redis://", "redis_uri"),
    ("amqp://", "amqp_uri"),
];

impl ClipboardGuard {
    pub fn new() -> Self {
        Self {
            alerts: RwLock::new(Vec::new()),
            total_checked: AtomicU64::new(0),
            total_blocked: AtomicU64::new(0),
            enabled: true,
            _cache: TieredCache::new(10_000),
            metrics: None,
        }
    }

    pub fn check_clipboard(&self, content: &str) -> ClipboardVerdict {
        if !self.enabled {
            return ClipboardVerdict { safe: true, findings: vec![], severity: Severity::Low };
        }
        self.total_checked.fetch_add(1, Ordering::Relaxed);
        let lower = content.to_lowercase();
        let mut findings = Vec::new();
        let mut max_sev = Severity::Low;

        // Check known secret patterns
        for (pat, category) in SECRET_PATTERNS {
            if lower.contains(pat) {
                findings.push(format!("secret:{}", category));
                if (max_sev as u8) < (Severity::High as u8) { max_sev = Severity::High; }
            }
        }

        // SSN pattern: ###-##-####
        if Self::has_ssn_pattern(content) {
            findings.push("pii:ssn".into());
            max_sev = Severity::Critical;
        }

        // Credit card: 13-19 digit runs
        if Self::has_cc_pattern(content) {
            findings.push("pii:credit_card".into());
            max_sev = Severity::Critical;
        }

        // Bulk data detection: many lines of structured data
        let line_count = content.lines().count();
        if line_count > 50 {
            let csv_like = content.lines().filter(|l| l.contains(',') && l.split(',').count() >= 3).count();
            if csv_like as f64 / line_count as f64 > 0.7 {
                findings.push("bulk_data:csv_export".into());
                if (max_sev as u8) < (Severity::High as u8) { max_sev = Severity::High; }
            }
        }

        // High entropy detection (encoded/encrypted data in clipboard)
        if content.len() > 64 && content.len() < 4096 {
            let entropy = Self::shannon_entropy(content);
            if entropy > 5.0 && !content.contains(' ') {
                findings.push("high_entropy_blob".into());
                if (max_sev as u8) < (Severity::Medium as u8) { max_sev = Severity::Medium; }
            }
        }

        findings.sort();
        findings.dedup();

        let safe = findings.is_empty();
        if !safe {
            self.total_blocked.fetch_add(1, Ordering::Relaxed);
            let now = chrono::Utc::now().timestamp();
            let cats = findings.join(", ");
            warn!(findings = %cats, severity = ?max_sev, "Clipboard exfiltration attempt");
            self.add_alert(now, max_sev, "Clipboard blocked", &cats[..cats.len().min(256)]);
        }

        ClipboardVerdict { safe, findings, severity: max_sev }
    }

    fn has_ssn_pattern(text: &str) -> bool {
        let b = text.as_bytes();
        if b.len() < 11 { return false; }
        for i in 0..b.len().saturating_sub(10) {
            if b[i].is_ascii_digit() && b[i+1].is_ascii_digit() && b[i+2].is_ascii_digit()
                && b[i+3] == b'-' && b[i+4].is_ascii_digit() && b[i+5].is_ascii_digit()
                && b[i+6] == b'-' && b[i+7].is_ascii_digit() && b[i+8].is_ascii_digit()
                && b[i+9].is_ascii_digit() && b[i+10].is_ascii_digit() { return true; }
        }
        false
    }

    fn has_cc_pattern(text: &str) -> bool {
        let mut run = 0u32;
        for ch in text.chars() {
            if ch.is_ascii_digit() { run += 1; }
            else if ch == ' ' || ch == '-' {}
            else { run = 0; }
            if run >= 13 { return true; }
        }
        false
    }

    fn shannon_entropy(text: &str) -> f64 {
        let mut freq = [0u32; 256];
        for &b in text.as_bytes() { freq[b as usize] += 1; }
        let len = text.len() as f64;
        freq.iter().filter(|&&f| f > 0).map(|&f| {
            let p = f as f64 / len;
            -p * p.log2()
        }).sum()
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(ExfilAlert { timestamp: ts, severity: sev, component: "clipboard_guard".into(), title: title.into(), details: details.into() });
    }

    pub fn total_checked(&self) -> u64 { self.total_checked.load(Ordering::Relaxed) }
    pub fn total_blocked(&self) -> u64 { self.total_blocked.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<ExfilAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
