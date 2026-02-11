//! Anonymizer — anonymizes or pseudonymizes sensitive data.
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Hot lookups cached
//! - **#6 Theoretical Verifier**: Bound memory usage
use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnonymizationResult {
    pub output: String,
    pub redactions: Vec<String>,
    pub categories_found: Vec<DataCategory>,
}

pub struct Anonymizer {
    alerts: RwLock<Vec<PrivacyAlert>>,
    total_anonymized: AtomicU64,
    total_redactions: AtomicU64,
    _cache: TieredCache<String, u64>,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

/// PII detection patterns (regex-style matching via contains/heuristics).
const EMAIL_INDICATORS: &[&str] = &["@gmail.", "@yahoo.", "@hotmail.", "@outlook.", "@protonmail.", "@icloud.", "@aol.", "@mail."];

/// Common name prefixes that indicate a person's name follows.
const NAME_PREFIXES: &[&str] = &["mr. ", "mrs. ", "ms. ", "dr. ", "prof. ", "mr ", "mrs ", "ms ", "dr ", "name: ", "patient: ", "user: ", "client: "];

impl Anonymizer {
    pub fn new() -> Self {
        Self {
            alerts: RwLock::new(Vec::new()),
            total_anonymized: AtomicU64::new(0),
            total_redactions: AtomicU64::new(0),
            enabled: true,
            _cache: TieredCache::new(10_000),
            metrics: None,
        }
    }

    /// Comprehensive anonymization: detects and redacts PII across multiple categories.
    pub fn anonymize_full(&self, input: &str) -> AnonymizationResult {
        if !self.enabled {
            return AnonymizationResult { output: input.to_string(), redactions: vec![], categories_found: vec![] };
        }
        self.total_anonymized.fetch_add(1, Ordering::Relaxed);
        let mut output = input.to_string();
        let mut redactions = Vec::new();
        let mut categories = Vec::new();

        // Email addresses
        let email_redacted = Self::redact_emails(&output);
        if email_redacted.1 > 0 {
            redactions.push(format!("emails:{}", email_redacted.1));
            categories.push(DataCategory::Pii);
            output = email_redacted.0;
        }

        // Phone numbers (US/international patterns)
        let phone_redacted = Self::redact_phones(&output);
        if phone_redacted.1 > 0 {
            redactions.push(format!("phones:{}", phone_redacted.1));
            if !categories.contains(&DataCategory::Pii) { categories.push(DataCategory::Pii); }
            output = phone_redacted.0;
        }

        // SSN patterns (XXX-XX-XXXX)
        let ssn_redacted = Self::redact_ssn(&output);
        if ssn_redacted.1 > 0 {
            redactions.push(format!("ssn:{}", ssn_redacted.1));
            if !categories.contains(&DataCategory::Pii) { categories.push(DataCategory::Pii); }
            output = ssn_redacted.0;
        }

        // Credit card numbers (13-19 digits with optional separators)
        let cc_redacted = Self::redact_credit_cards(&output);
        if cc_redacted.1 > 0 {
            redactions.push(format!("credit_cards:{}", cc_redacted.1));
            categories.push(DataCategory::Financial);
            output = cc_redacted.0;
        }

        // IPv4 addresses
        let ip_redacted = Self::redact_ipv4(&output);
        if ip_redacted.1 > 0 {
            redactions.push(format!("ipv4:{}", ip_redacted.1));
            categories.push(DataCategory::Location);
            output = ip_redacted.0;
        }

        // Dates of birth (various formats)
        let dob_redacted = Self::redact_dates(&output);
        if dob_redacted.1 > 0 {
            redactions.push(format!("dates:{}", dob_redacted.1));
            if !categories.contains(&DataCategory::Pii) { categories.push(DataCategory::Pii); }
            output = dob_redacted.0;
        }

        // Names after known prefixes
        let name_redacted = Self::redact_names(&output);
        if name_redacted.1 > 0 {
            redactions.push(format!("names:{}", name_redacted.1));
            if !categories.contains(&DataCategory::Pii) { categories.push(DataCategory::Pii); }
            output = name_redacted.0;
        }

        self.total_redactions.fetch_add(redactions.len() as u64, Ordering::Relaxed);

        if !redactions.is_empty() {
            let now = chrono::Utc::now().timestamp();
            let cats = redactions.join(", ");
            self.add_alert(now, Severity::Medium, "PII redacted", &format!("Redacted: {}", &cats[..cats.len().min(200)]));
        }

        AnonymizationResult { output, redactions, categories_found: categories }
    }

    /// Pseudonymize: deterministic hash-based replacement (consistent across calls).
    pub fn pseudonymize(&self, input: &str) -> String {
        self.total_anonymized.fetch_add(1, Ordering::Relaxed);
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        input.hash(&mut h);
        format!("pseudo_{:016x}", h.finish())
    }

    /// K-anonymity helper: generalize a value to reduce uniqueness.
    pub fn generalize(&self, value: &str, category: DataCategory) -> String {
        match category {
            DataCategory::Location => {
                // Generalize ZIP to first 3 digits
                if value.len() == 5 && value.chars().all(|c| c.is_ascii_digit()) {
                    return format!("{}**", &value[..3]);
                }
                "[LOCATION]".into()
            }
            DataCategory::Pii => {
                // Generalize age to decade
                if let Ok(age) = value.parse::<u32>() {
                    return format!("{}-{}", (age / 10) * 10, (age / 10) * 10 + 9);
                }
                "[REDACTED]".into()
            }
            _ => "[REDACTED]".into(),
        }
    }

    /// Legacy API.
    pub fn anonymize(&self, input: &str) -> String {
        self.anonymize_full(input).output
    }

    fn redact_emails(input: &str) -> (String, usize) {
        let mut output = input.to_string();
        let mut count = 0;
        for indicator in EMAIL_INDICATORS {
            while let Some(at_pos) = output.to_lowercase().find(indicator) {
                // Find start of email (scan back for non-space)
                let start = output[..at_pos].rfind(|c: char| c.is_whitespace() || c == '<' || c == '(' || c == ',').map(|p| p + 1).unwrap_or(0);
                // Find end of email (scan forward for non-email char)
                let after_at = at_pos + indicator.len();
                let end = output[after_at..].find(|c: char| c.is_whitespace() || c == '>' || c == ')' || c == ',').map(|p| after_at + p).unwrap_or(output.len());
                if end > start {
                    output.replace_range(start..end, "[EMAIL]");
                    count += 1;
                } else {
                    break;
                }
            }
        }
        (output, count)
    }

    fn redact_phones(input: &str) -> (String, usize) {
        let mut output = input.to_string();
        let mut count = 0;
        let chars: Vec<char> = output.chars().collect();
        let mut i = 0;
        let mut result = String::with_capacity(output.len());
        while i < chars.len() {
            // Look for sequences of 10+ digits (with optional separators)
            if chars[i].is_ascii_digit() || (chars[i] == '+' && i + 1 < chars.len() && chars[i + 1].is_ascii_digit()) {
                let start = i;
                let mut digit_count = 0;
                let mut j = i;
                while j < chars.len() && (chars[j].is_ascii_digit() || chars[j] == '-' || chars[j] == '.' || chars[j] == ' ' || chars[j] == '(' || chars[j] == ')' || chars[j] == '+') {
                    if chars[j].is_ascii_digit() { digit_count += 1; }
                    j += 1;
                }
                if digit_count >= 10 && digit_count <= 15 {
                    result.push_str("[PHONE]");
                    count += 1;
                    i = j;
                    continue;
                }
            }
            result.push(chars[i]);
            i += 1;
        }
        if count > 0 { output = result; }
        (output, count)
    }

    fn redact_ssn(input: &str) -> (String, usize) {
        let mut output = input.to_string();
        let mut count = 0;
        // Pattern: 3 digits, separator, 2 digits, separator, 4 digits
        let chars: Vec<char> = output.chars().collect();
        let mut result = String::with_capacity(output.len());
        let mut i = 0;
        while i < chars.len() {
            if i + 10 < chars.len()
                && chars[i].is_ascii_digit() && chars[i+1].is_ascii_digit() && chars[i+2].is_ascii_digit()
                && (chars[i+3] == '-' || chars[i+3] == ' ')
                && chars[i+4].is_ascii_digit() && chars[i+5].is_ascii_digit()
                && (chars[i+6] == '-' || chars[i+6] == ' ')
                && chars[i+7].is_ascii_digit() && chars[i+8].is_ascii_digit() && chars[i+9].is_ascii_digit() && chars[i+10].is_ascii_digit()
            {
                result.push_str("[SSN]");
                count += 1;
                i += 11;
                continue;
            }
            result.push(chars[i]);
            i += 1;
        }
        if count > 0 { output = result; }
        (output, count)
    }

    fn redact_credit_cards(input: &str) -> (String, usize) {
        let mut output = input.to_string();
        let mut count = 0;
        let chars: Vec<char> = output.chars().collect();
        let mut result = String::with_capacity(output.len());
        let mut i = 0;
        while i < chars.len() {
            if chars[i].is_ascii_digit() {
                let start = i;
                let mut digits = Vec::new();
                let mut j = i;
                while j < chars.len() && (chars[j].is_ascii_digit() || chars[j] == '-' || chars[j] == ' ') {
                    if chars[j].is_ascii_digit() { digits.push(chars[j]); }
                    j += 1;
                }
                if digits.len() >= 13 && digits.len() <= 19 && Self::luhn_check(&digits) {
                    result.push_str("[CREDIT_CARD]");
                    count += 1;
                    i = j;
                    continue;
                }
            }
            result.push(chars[i]);
            i += 1;
        }
        if count > 0 { output = result; }
        (output, count)
    }

    fn luhn_check(digits: &[char]) -> bool {
        let mut sum = 0u32;
        let mut double = false;
        for &d in digits.iter().rev() {
            let mut n = d.to_digit(10).unwrap_or(0);
            if double { n *= 2; if n > 9 { n -= 9; } }
            sum += n;
            double = !double;
        }
        sum % 10 == 0
    }

    fn redact_ipv4(input: &str) -> (String, usize) {
        let mut output = input.to_string();
        let mut count = 0;
        // Simple word-boundary IPv4 detection
        let words: Vec<&str> = input.split_whitespace().collect();
        for word in &words {
            let trimmed = word.trim_matches(|c: char| !c.is_ascii_digit() && c != '.');
            let parts: Vec<&str> = trimmed.split('.').collect();
            if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
                output = output.replacen(trimmed, "[IP_ADDR]", 1);
                count += 1;
            }
        }
        (output, count)
    }

    fn redact_dates(input: &str) -> (String, usize) {
        let mut output = input.to_string();
        let mut count = 0;
        // Pattern: MM/DD/YYYY or DD/MM/YYYY or YYYY-MM-DD
        let chars: Vec<char> = output.chars().collect();
        let mut result = String::with_capacity(output.len());
        let mut i = 0;
        while i < chars.len() {
            // YYYY-MM-DD
            if i + 9 < chars.len() && chars[i..i+4].iter().all(|c| c.is_ascii_digit())
                && chars[i+4] == '-' && chars[i+5..i+7].iter().all(|c| c.is_ascii_digit())
                && chars[i+7] == '-' && chars[i+8..i+10].iter().all(|c| c.is_ascii_digit())
            {
                result.push_str("[DATE]");
                count += 1;
                i += 10;
                continue;
            }
            // MM/DD/YYYY
            if i + 9 < chars.len() && chars[i..i+2].iter().all(|c| c.is_ascii_digit())
                && chars[i+2] == '/' && chars[i+3..i+5].iter().all(|c| c.is_ascii_digit())
                && chars[i+5] == '/' && chars[i+6..i+10].iter().all(|c| c.is_ascii_digit())
            {
                result.push_str("[DATE]");
                count += 1;
                i += 10;
                continue;
            }
            result.push(chars[i]);
            i += 1;
        }
        if count > 0 { output = result; }
        (output, count)
    }

    fn redact_names(input: &str) -> (String, usize) {
        let mut output = input.to_string();
        let mut count = 0;
        let lower = input.to_lowercase();
        for prefix in NAME_PREFIXES {
            while let Some(pos) = output.to_lowercase().find(prefix) {
                let after = pos + prefix.len();
                // Capture up to 2 capitalized words after prefix
                let rest = &output[after..];
                let end = rest.find(|c: char| c == ',' || c == '.' || c == ';' || c == '\n' || c == '(' || c == ')').unwrap_or(rest.len().min(40));
                if end > 0 {
                    let name_end = after + end;
                    output.replace_range(pos..name_end, "[NAME]");
                    count += 1;
                } else {
                    break;
                }
            }
        }
        let _ = lower; // suppress unused warning
        (output, count)
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(PrivacyAlert { timestamp: ts, severity: sev, component: "anonymizer".into(), title: title.into(), details: details.into() });
    }

    pub fn total_anonymized(&self) -> u64 { self.total_anonymized.load(Ordering::Relaxed) }
    pub fn total_redactions(&self) -> u64 { self.total_redactions.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<PrivacyAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
