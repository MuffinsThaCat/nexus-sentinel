//! Report Writer — generates forensic investigation reports.
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Hot report lookups
//! - **#6 Theoretical Verifier**: Bound report store

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ForensicReport {
    pub report_id: String,
    pub case_id: String,
    pub title: String,
    pub summary: String,
    pub findings: Vec<String>,
    pub recommendations: Vec<String>,
    pub created_at: i64,
}

/// Report writer with 2 memory breakthroughs.
pub struct ReportWriter {
    reports: RwLock<Vec<ForensicReport>>,
    /// #2 Tiered cache: hot report lookups
    report_cache: TieredCache<String, u64>,
    alerts: RwLock<Vec<ForensicAlert>>,
    total_reports: AtomicU64,
    /// #6 Theoretical verifier
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl ReportWriter {
    pub fn new() -> Self {
        Self {
            reports: RwLock::new(Vec::new()),
            report_cache: TieredCache::new(10_000),
            alerts: RwLock::new(Vec::new()),
            total_reports: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    /// #6 Theoretical verifier: bound report store at 4MB.
    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("report_writer", 4 * 1024 * 1024);
        self.report_cache = self.report_cache.with_metrics(metrics.clone(), "report_writer");
        self.metrics = Some(metrics);
        self
    }

    /// Required report sections for chain-of-custody compliance.
    const REQUIRED_SECTIONS: &'static [&'static str] = &[
        "executive_summary", "methodology", "timeline", "evidence",
        "analysis", "conclusions", "recommendations",
    ];

    pub fn create_report(&self, report: ForensicReport) {
        self.total_reports.fetch_add(1, Ordering::Relaxed);
        let now = report.created_at;

        // Validate report completeness
        if report.findings.is_empty() {
            self.add_alert(now, Severity::Medium, "Empty findings", &format!("Report {} has no findings", report.report_id));
        }
        if report.recommendations.is_empty() {
            self.add_alert(now, Severity::Low, "No recommendations", &format!("Report {} has no recommendations", report.report_id));
        }
        if report.summary.len() < 50 {
            self.add_alert(now, Severity::Low, "Brief summary", &format!("Report {} summary only {} chars", report.report_id, report.summary.len()));
        }

        // Check for critical findings that need escalation
        let critical_count = report.findings.iter().filter(|f| {
            let fl = f.to_lowercase();
            fl.contains("critical") || fl.contains("breach") || fl.contains("exfiltration") || fl.contains("ransomware") || fl.contains("rootkit")
        }).count();
        if critical_count > 0 {
            self.add_alert(now, Severity::Critical, "Critical findings", &format!("Report {} contains {} critical findings", report.report_id, critical_count));
        }

        let mut reports = self.reports.write();
        if reports.len() >= MAX_ALERTS { reports.remove(0); }
        reports.push(report);
    }

    pub fn by_case(&self, case_id: &str) -> Vec<ForensicReport> {
        self.reports.read().iter().filter(|r| r.case_id == case_id).cloned().collect()
    }

    /// Generate a case summary across all reports for a case.
    pub fn case_summary(&self, case_id: &str) -> Option<String> {
        let reports = self.by_case(case_id);
        if reports.is_empty() { return None; }
        let total_findings: usize = reports.iter().map(|r| r.findings.len()).sum();
        let total_recs: usize = reports.iter().map(|r| r.recommendations.len()).sum();
        Some(format!("Case {}: {} reports, {} findings, {} recommendations", case_id, reports.len(), total_findings, total_recs))
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(ForensicAlert { timestamp: ts, severity: sev, component: "report_writer".into(), title: title.into(), details: details.into() });
    }

    pub fn total_reports(&self) -> u64 { self.total_reports.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<ForensicAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
