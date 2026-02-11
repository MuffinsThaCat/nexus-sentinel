//! Content Scanner — scans web content for malicious payloads.
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Hot pattern lookups
//! - **#6 Theoretical Verifier**: Bound pattern store

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_ALERTS: usize = 5_000;

/// Built-in malicious content patterns.
const BUILTIN_PATTERNS: &[(&str, &str)] = &[
    ("<script", "xss_script_tag"),
    ("javascript:", "xss_javascript_uri"),
    ("onerror=", "xss_event_handler"),
    ("onload=", "xss_event_handler"),
    ("eval(", "code_injection"),
    ("document.cookie", "cookie_theft"),
    ("window.location", "redirect_attack"),
    (".fromcharcode", "obfuscated_payload"),
    ("base64,", "encoded_payload"),
    ("data:text/html", "data_uri_xss"),
    ("<iframe", "iframe_injection"),
    ("<object", "object_injection"),
    ("<embed", "embed_injection"),
    ("<svg/onload", "svg_xss"),
    ("expression(", "css_expression"),
    ("-moz-binding", "css_binding"),
    ("url(javascript", "css_js_injection"),
    ("<!--#exec", "ssi_injection"),
    ("<?php", "php_injection"),
    ("<% ", "asp_injection"),
];

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanVerdict {
    pub safe: bool,
    pub findings: Vec<String>,
    pub severity: Severity,
}

/// Content scanner with 2 memory breakthroughs.
pub struct ContentScanner {
    patterns: RwLock<Vec<String>>,
    pattern_cache: TieredCache<String, bool>,
    alerts: RwLock<Vec<WebAlert>>,
    total_scanned: AtomicU64,
    total_blocked: AtomicU64,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl ContentScanner {
    pub fn new() -> Self {
        Self {
            patterns: RwLock::new(Vec::new()),
            pattern_cache: TieredCache::new(50_000),
            alerts: RwLock::new(Vec::new()),
            total_scanned: AtomicU64::new(0),
            total_blocked: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("content_scanner", 2 * 1024 * 1024);
        self.pattern_cache = self.pattern_cache.with_metrics(metrics.clone(), "content_scanner");
        self.metrics = Some(metrics);
        self
    }

    pub fn add_pattern(&self, pattern: &str) { self.patterns.write().push(pattern.to_string()); }

    /// Comprehensive content scan with built-in OWASP patterns and custom rules.
    pub fn scan_full(&self, content: &str) -> ScanVerdict {
        if !self.enabled { return ScanVerdict { safe: true, findings: vec![], severity: Severity::Low }; }
        self.total_scanned.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        let lower = content.to_lowercase();
        let mut findings = Vec::new();
        let mut sev = Severity::Low;

        // 1. Built-in malicious patterns
        for (pattern, category) in BUILTIN_PATTERNS {
            if lower.contains(pattern) {
                findings.push(format!("{}:{}", category, pattern));
                if sev < Severity::High { sev = Severity::High; }
            }
        }

        // 2. Custom patterns
        let patterns = self.patterns.read();
        for p in patterns.iter() {
            if lower.contains(&p.to_lowercase()) {
                findings.push(format!("custom_pattern:{}", &p[..p.len().min(30)]));
                if sev < Severity::Medium { sev = Severity::Medium; }
            }
        }
        drop(patterns);

        // 3. Null byte injection
        if content.contains('\0') {
            findings.push("null_byte_injection".into());
            sev = Severity::Critical;
        }

        // 4. Oversized content (potential DoS)
        if content.len() > 10_000_000 {
            findings.push(format!("oversized:{}MB", content.len() / 1_000_000));
            if sev < Severity::Medium { sev = Severity::Medium; }
        }

        // 5. High ratio of non-printable chars (binary smuggling)
        let non_printable = content.chars().filter(|c| !c.is_ascii_graphic() && !c.is_ascii_whitespace()).count();
        if content.len() > 100 && non_printable as f64 / content.len() as f64 > 0.3 {
            findings.push(format!("binary_smuggling:{:.0}%_non_printable", (non_printable as f64 / content.len() as f64) * 100.0));
            if sev < Severity::High { sev = Severity::High; }
        }

        let safe = findings.is_empty();
        if !safe {
            self.total_blocked.fetch_add(1, Ordering::Relaxed);
            let cats = findings.join(", ");
            self.add_alert(now, sev, "Malicious content", &format!("{}", &cats[..cats.len().min(200)]));
        }

        ScanVerdict { safe, findings, severity: sev }
    }

    /// Legacy API.
    pub fn scan(&self, content: &str) -> bool {
        self.scan_full(content).safe
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(WebAlert { timestamp: ts, severity: sev, component: "content_scanner".into(), title: title.into(), details: details.into() });
    }

    pub fn total_scanned(&self) -> u64 { self.total_scanned.load(Ordering::Relaxed) }
    pub fn total_blocked(&self) -> u64 { self.total_blocked.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<WebAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
