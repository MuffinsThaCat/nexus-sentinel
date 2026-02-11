//! QR Code Scanner — extracts and validates URLs from QR codes.
//!
//! Memory optimizations (1 technique):
//! - **#6 Theoretical Verifier**: Stateless — minimal memory

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QrScanResult {
    pub extracted_url: String,
    pub safe: bool,
    pub scanned_at: i64,
}

/// QR code scanner — minimal memory.
pub struct QrScanner {
    results: RwLock<Vec<QrScanResult>>,
    url_cache: TieredCache<String, bool>,
    alerts: RwLock<Vec<PhishingAlert>>,
    total_scanned: AtomicU64,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl QrScanner {
    pub fn new() -> Self {
        Self {
            results: RwLock::new(Vec::new()),
            url_cache: TieredCache::new(10_000),
            alerts: RwLock::new(Vec::new()),
            total_scanned: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("qr_scanner", 1024 * 1024);
        self.url_cache = self.url_cache.with_metrics(metrics.clone(), "qr_scanner");
        self.metrics = Some(metrics);
        self
    }

    /// Known URL shortener domains often used to hide phishing URLs in QR codes.
    const URL_SHORTENERS: &'static [&'static str] = &[
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
        "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
    ];

    /// Suspicious TLDs frequently used in phishing.
    const SUSPICIOUS_TLDS: &'static [&'static str] = &[
        ".xyz", ".top", ".club", ".work", ".click", ".link",
        ".info", ".online", ".site", ".icu", ".buzz",
    ];

    /// Scan a QR code URL with built-in heuristic analysis.
    pub fn scan_qr(&self, extracted_url: &str, is_safe: bool) -> QrScanResult {
        self.total_scanned.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        let url_lower = extracted_url.to_lowercase();
        let mut safe = is_safe;

        // 1. URL shortener detection (hide real destination)
        if Self::URL_SHORTENERS.iter().any(|s| url_lower.contains(s)) {
            self.add_alert(now, Severity::Medium, "QR URL shortener", &format!("Shortened URL: {}", &extracted_url[..extracted_url.len().min(100)]));
        }

        // 2. Suspicious TLD
        if Self::SUSPICIOUS_TLDS.iter().any(|tld| url_lower.ends_with(tld) || url_lower.contains(&format!("{}/", tld))) {
            self.add_alert(now, Severity::High, "Suspicious QR TLD", &format!("Suspicious TLD in {}", &extracted_url[..extracted_url.len().min(100)]));
            safe = false;
        }

        // 3. Data URI (can embed malicious HTML/JS)
        if url_lower.starts_with("data:") {
            self.add_alert(now, Severity::Critical, "QR data URI", "QR code contains embedded data URI (potential XSS)");
            safe = false;
        }

        // 4. Non-HTTPS (credential theft risk)
        if url_lower.starts_with("http://") && !url_lower.contains("localhost") {
            self.add_alert(now, Severity::Medium, "Insecure QR URL", &format!("Non-HTTPS: {}", &extracted_url[..extracted_url.len().min(100)]));
        }

        // 5. Homograph attack detection (mixed scripts in URL)
        let has_non_ascii = extracted_url.chars().any(|c| !c.is_ascii());
        if has_non_ascii {
            self.add_alert(now, Severity::High, "IDN homograph", &format!("Non-ASCII chars in QR URL (homograph attack?): {}", &extracted_url[..extracted_url.len().min(60)]));
            safe = false;
        }

        // 6. Excessive URL length (obfuscation)
        if extracted_url.len() > 500 {
            self.add_alert(now, Severity::Medium, "Oversized QR URL", &format!("URL length {} chars", extracted_url.len()));
        }

        if !safe {
            warn!(url = %&extracted_url[..extracted_url.len().min(100)], "Malicious QR code URL");
            self.add_alert(now, Severity::High, "Malicious QR URL", &extracted_url[..extracted_url.len().min(200)]);
        }

        let result = QrScanResult { extracted_url: extracted_url.into(), safe, scanned_at: now };
        let mut r = self.results.write();
        if r.len() >= MAX_ALERTS { r.remove(0); }
        r.push(result.clone());
        result
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(PhishingAlert { timestamp: ts, severity: sev, component: "qr_scanner".into(), title: title.into(), details: details.into() });
    }

    pub fn total_scanned(&self) -> u64 { self.total_scanned.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<PhishingAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
