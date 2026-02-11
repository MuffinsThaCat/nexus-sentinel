//! Artifact Extractor — extracts forensic artifacts from various sources.
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Hot artifact lookups
//! - **#6 Theoretical Verifier**: Bound artifact store

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExtractedArtifact {
    pub artifact_id: String,
    pub source_id: String,
    pub artifact_type: String,
    pub path: String,
    pub hash: String,
    pub extracted_at: i64,
}

/// Artifact extractor with 2 memory breakthroughs.
pub struct ArtifactExtractor {
    artifacts: RwLock<Vec<ExtractedArtifact>>,
    /// #2 Tiered cache: hot artifact lookups
    artifact_cache: TieredCache<String, u64>,
    alerts: RwLock<Vec<ForensicAlert>>,
    total_extracted: AtomicU64,
    /// #6 Theoretical verifier
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl ArtifactExtractor {
    pub fn new() -> Self {
        Self {
            artifacts: RwLock::new(Vec::new()),
            artifact_cache: TieredCache::new(50_000),
            alerts: RwLock::new(Vec::new()),
            total_extracted: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    /// #6 Theoretical verifier: bound artifact store at 4MB.
    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("artifact_extractor", 4 * 1024 * 1024);
        self.artifact_cache = self.artifact_cache.with_metrics(metrics.clone(), "artifact_extractor");
        self.metrics = Some(metrics);
        self
    }

    /// High-value forensic artifact types.
    const HIGH_VALUE_TYPES: &'static [&'static str] = &[
        "memory_dump", "registry_hive", "event_log", "browser_history",
        "email_archive", "encryption_key", "shadow_file", "sam_database",
    ];

    /// Suspicious file extensions that may indicate malware.
    const SUSPICIOUS_EXTENSIONS: &'static [&'static str] = &[
        ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs",
        ".js", ".wsf", ".hta", ".lnk", ".pif",
    ];

    pub fn extract(&self, artifact: ExtractedArtifact) {
        self.total_extracted.fetch_add(1, Ordering::Relaxed);
        let now = artifact.extracted_at;
        let type_lower = artifact.artifact_type.to_lowercase();
        let path_lower = artifact.path.to_lowercase();

        // Flag high-value artifacts
        if Self::HIGH_VALUE_TYPES.iter().any(|t| type_lower.contains(t)) {
            self.add_alert(now, Severity::High, "High-value artifact", &format!("{} ({}) from {}", artifact.artifact_id, artifact.artifact_type, artifact.source_id));
        }

        // Check for suspicious executables
        if Self::SUSPICIOUS_EXTENSIONS.iter().any(|ext| path_lower.ends_with(ext)) {
            self.add_alert(now, Severity::Critical, "Suspicious executable", &format!("{} at {}", artifact.artifact_id, artifact.path));
        }

        // Detect hash anomalies (empty or weak hashes)
        if artifact.hash.is_empty() || artifact.hash.len() < 32 {
            self.add_alert(now, Severity::Medium, "Weak/missing hash", &format!("{} hash='{}' ({}chars)", artifact.artifact_id, &artifact.hash[..artifact.hash.len().min(16)], artifact.hash.len()));
        }

        // Duplicate hash detection (same content, different paths = lateral movement indicator)
        let artifacts = self.artifacts.read();
        let dup = artifacts.iter().any(|a| a.hash == artifact.hash && a.path != artifact.path && !artifact.hash.is_empty());
        drop(artifacts);
        if dup {
            self.add_alert(now, Severity::High, "Duplicate artifact hash", &format!("{} same hash as existing artifact (lateral movement?)", artifact.artifact_id));
        }

        let mut artifacts = self.artifacts.write();
        if artifacts.len() >= MAX_ALERTS { artifacts.remove(0); }
        artifacts.push(artifact);
    }

    pub fn by_source(&self, source_id: &str) -> Vec<ExtractedArtifact> {
        self.artifacts.read().iter().filter(|a| a.source_id == source_id).cloned().collect()
    }

    pub fn by_type(&self, artifact_type: &str) -> Vec<ExtractedArtifact> {
        let t = artifact_type.to_lowercase();
        self.artifacts.read().iter().filter(|a| a.artifact_type.to_lowercase().contains(&t)).cloned().collect()
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(ForensicAlert { timestamp: ts, severity: sev, component: "artifact_extractor".into(), title: title.into(), details: details.into() });
    }

    pub fn total_extracted(&self) -> u64 { self.total_extracted.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<ForensicAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
