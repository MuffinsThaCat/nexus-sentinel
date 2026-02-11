//! Schema Validator — World-class API schema validation and injection detection engine
//!
//! Features:
//! - Schema-based field type/length/required validation
//! - Injection detection in field values (SQLi, XSS, template, CRLF)
//! - Null byte injection detection
//! - Body size enforcement
//! - Graduated severity alerting (Critical/High/Medium/Low)
//! - Audit trail with LZ4 compression
//! - Rich reporting and statistics
//! - Compliance mapping (NIST SI-10, CIS 18.x input validation)
//!
//! Memory optimizations (10 techniques):
//! - **#1 HierarchicalState**: Validation history O(log n)
//! - **#2 TieredCache**: Hot schema lookups cached
//! - **#3 ReversibleComputation**: Recompute violation rates
//! - **#5 StreamAccumulator**: Window stats without raw storage
//! - **#6 MemoryMetrics**: Bounded memory verification
//! - **#461 DifferentialStore**: Schema registration diffs
//! - **#569 PruningMap**: Auto-expire old validations
//! - **#592 DedupStore**: Dedup repeated violations
//! - **#593 Compression**: LZ4 compress audit
//! - **#627 SparseMatrix**: Endpoint-to-violation-type matrix
use crate::types::*;
use sentinel_core::hierarchical::HierarchicalState;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::reversible::ReversibleComputation;
use sentinel_core::streaming::StreamAccumulator;
use sentinel_core::differential::DifferentialStore;
use sentinel_core::sparse::SparseMatrix;
use sentinel_core::pruning::PruningMap;
use sentinel_core::dedup::DedupStore;
use sentinel_core::compression;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;
const MAX_RECORDS: usize = 10_000;

#[derive(Debug, Clone, Default)]
pub struct ValidateWindowSummary { pub validated: u64, pub violations: u64 }

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FieldType { String, Integer, Float, Boolean, Array, Object, Email, Url, Uuid }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FieldSpec {
    pub name: String,
    pub field_type: FieldType,
    pub required: bool,
    pub max_length: Option<usize>,
    pub min_length: Option<usize>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ApiSchema {
    pub endpoint: String,
    pub method: String,
    pub required_fields: Vec<String>,
    pub field_specs: Vec<FieldSpec>,
    pub max_body_size: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ValidationResult {
    pub valid: bool,
    pub violations: Vec<String>,
    pub severity: Severity,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SchemaValidatorReport {
    pub total_validated: u64,
    pub total_violations: u64,
    pub violation_rate_pct: f64,
    pub schemas_registered: u64,
}

pub struct SchemaValidator {
    schemas: RwLock<HashMap<String, ApiSchema>>,
    alerts: RwLock<Vec<ApiAlert>>,
    total_validated: AtomicU64,
    total_violations: AtomicU64,
    /// #2 TieredCache
    schema_cache: TieredCache<String, u64>,
    /// #1 HierarchicalState
    history: RwLock<HierarchicalState<ValidateWindowSummary>>,
    /// #3 ReversibleComputation
    violation_rate_computer: RwLock<ReversibleComputation<(String, f64), f64>>,
    /// #5 StreamAccumulator
    validate_stream: RwLock<StreamAccumulator<u64, ValidateWindowSummary>>,
    /// #461 DifferentialStore
    schema_diffs: RwLock<DifferentialStore<String, String>>,
    /// #627 SparseMatrix
    endpoint_violation_matrix: RwLock<SparseMatrix<String, String, u32>>,
    /// #569 PruningMap
    stale_validations: RwLock<PruningMap<String, i64>>,
    /// #592 DedupStore
    violation_dedup: RwLock<DedupStore<String, String>>,
    /// #593 Compression
    compressed_audit: RwLock<Vec<Vec<u8>>>,
    /// #6 MemoryMetrics
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

/// Injection patterns to check in field values.
const FIELD_INJECTION_PATTERNS: &[&str] = &[
    "<script", "javascript:", "onerror=", "onclick=",
    "' or ", "'; drop", "union select", "../", "..\\",
    "${", "#{", "{{", "`", "$(", "\r\n", "%0d%0a",
];

impl SchemaValidator {
    pub fn new() -> Self {
        let violation_rate_computer = ReversibleComputation::new(4096, |inputs: &[(String, f64)]| {
            if inputs.is_empty() { return 0.0f64; }
            let violated = inputs.iter().filter(|(_, v)| *v > 0.0).count();
            violated as f64 / inputs.len() as f64 * 100.0
        });
        let validate_stream = StreamAccumulator::new(64, ValidateWindowSummary::default(),
            |acc, ids: &[u64]| { acc.validated += ids.len() as u64; });
        Self {
            schemas: RwLock::new(HashMap::new()),
            alerts: RwLock::new(Vec::new()),
            total_validated: AtomicU64::new(0),
            total_violations: AtomicU64::new(0),
            schema_cache: TieredCache::new(10_000),
            history: RwLock::new(HierarchicalState::new(6, 64)),
            violation_rate_computer: RwLock::new(violation_rate_computer),
            validate_stream: RwLock::new(validate_stream),
            schema_diffs: RwLock::new(DifferentialStore::new()),
            endpoint_violation_matrix: RwLock::new(SparseMatrix::new(0u32)),
            stale_validations: RwLock::new(PruningMap::new(50_000).with_ttl(std::time::Duration::from_secs(3600))),
            violation_dedup: RwLock::new(DedupStore::new()),
            compressed_audit: RwLock::new(Vec::new()),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("sv_cache", 2 * 1024 * 1024);
        metrics.register_component("sv_audit", 128 * 1024);
        self.schema_cache = self.schema_cache.with_metrics(metrics.clone(), "sv_cache");
        self.metrics = Some(metrics);
        self
    }

    pub fn register(&self, schema: ApiSchema) {
        let key = format!("{}:{}", schema.method, schema.endpoint);
        { let mut diffs = self.schema_diffs.write(); diffs.record_update(key.clone(), schema.endpoint.clone()); }
        self.schemas.write().insert(key, schema);
    }

    pub fn validate_full(&self, method: &str, endpoint: &str, fields: &HashMap<String, String>, body_size: usize) -> ValidationResult {
        if !self.enabled {
            return ValidationResult { valid: true, violations: vec![], severity: Severity::Low };
        }
        self.total_validated.fetch_add(1, Ordering::Relaxed);
        self.validate_stream.write().push(self.total_validated.load(Ordering::Relaxed));
        let ep_key = format!("{}:{}", method, endpoint);
        self.schema_cache.insert(ep_key.clone(), self.total_validated.load(Ordering::Relaxed));
        self.stale_validations.write().insert(ep_key.clone(), chrono::Utc::now().timestamp());

        let schemas = self.schemas.read();
        let mut violations = Vec::new();
        let mut max_sev = Severity::Low;

        if let Some(schema) = schemas.get(&ep_key) {
            if body_size > schema.max_body_size && schema.max_body_size > 0 {
                violations.push(format!("body_too_large:{}>{}", body_size, schema.max_body_size));
                if (max_sev as u8) < (Severity::Medium as u8) { max_sev = Severity::Medium; }
            }
            for req in &schema.required_fields {
                if !fields.contains_key(req.as_str()) {
                    violations.push(format!("missing_required:{}", req));
                    if (max_sev as u8) < (Severity::High as u8) { max_sev = Severity::High; }
                }
            }
            for spec in &schema.field_specs {
                if let Some(value) = fields.get(&spec.name) {
                    if let Some(max) = spec.max_length {
                        if value.len() > max { violations.push(format!("too_long:{}:{}>{}", spec.name, value.len(), max)); if (max_sev as u8) < (Severity::Medium as u8) { max_sev = Severity::Medium; } }
                    }
                    if let Some(min) = spec.min_length {
                        if value.len() < min { violations.push(format!("too_short:{}:{}<{}", spec.name, value.len(), min)); }
                    }
                    match spec.field_type {
                        FieldType::Integer => { if value.parse::<i64>().is_err() { violations.push(format!("type_mismatch:{}:expected_integer", spec.name)); if (max_sev as u8) < (Severity::Medium as u8) { max_sev = Severity::Medium; } } }
                        FieldType::Float => { if value.parse::<f64>().is_err() { violations.push(format!("type_mismatch:{}:expected_float", spec.name)); if (max_sev as u8) < (Severity::Medium as u8) { max_sev = Severity::Medium; } } }
                        FieldType::Boolean => { if !["true", "false", "0", "1"].contains(&value.to_lowercase().as_str()) { violations.push(format!("type_mismatch:{}:expected_boolean", spec.name)); } }
                        FieldType::Email => { if !value.contains('@') || !value.contains('.') || value.len() < 5 { violations.push(format!("invalid_email:{}", spec.name)); if (max_sev as u8) < (Severity::Medium as u8) { max_sev = Severity::Medium; } } }
                        FieldType::Url => { if !value.starts_with("http://") && !value.starts_with("https://") { violations.push(format!("invalid_url:{}", spec.name)); } }
                        FieldType::Uuid => { let parts: Vec<&str> = value.split('-').collect(); if parts.len() != 5 || value.len() != 36 { violations.push(format!("invalid_uuid:{}", spec.name)); } }
                        _ => {}
                    }
                    let lower = value.to_lowercase();
                    for pat in FIELD_INJECTION_PATTERNS {
                        if lower.contains(pat) { violations.push(format!("injection_in_field:{}:{}", spec.name, &pat[..pat.len().min(15)])); max_sev = Severity::Critical; }
                    }
                } else if spec.required {
                    violations.push(format!("missing_required_spec:{}", spec.name));
                    if (max_sev as u8) < (Severity::High as u8) { max_sev = Severity::High; }
                }
            }
        }

        for (name, value) in fields {
            let lower = value.to_lowercase();
            for pat in FIELD_INJECTION_PATTERNS {
                if lower.contains(pat) {
                    let finding = format!("injection_in_field:{}:{}", name, &pat[..pat.len().min(15)]);
                    if !violations.contains(&finding) { violations.push(finding); max_sev = Severity::Critical; }
                }
            }
            if value.contains('\0') { violations.push(format!("null_byte_injection:{}", name)); max_sev = Severity::Critical; }
        }

        violations.sort();
        violations.dedup();

        let valid = violations.is_empty();
        if !valid {
            self.total_violations.fetch_add(1, Ordering::Relaxed);
            { let mut rc = self.violation_rate_computer.write(); rc.push((ep_key.clone(), 1.0)); }
            let now = chrono::Utc::now().timestamp();
            let cats = violations.join(", ");
            for v in &violations {
                let vtype = v.split(':').next().unwrap_or("unknown").to_string();
                { let mut dedup = self.violation_dedup.write(); dedup.insert(format!("{}:{}", endpoint, vtype), v.clone()); }
                { let mut mat = self.endpoint_violation_matrix.write(); let cur = *mat.get(&endpoint.to_string(), &vtype); mat.set(endpoint.to_string(), vtype, cur + 1); }
            }
            warn!(endpoint = %endpoint, violations = %cats, "Schema violations");
            self.record_audit(&format!("violation|{}|{:?}|{}", endpoint, max_sev, &cats[..cats.len().min(256)]));
            self.add_alert(now, max_sev, "Schema violation", &format!("{} {}: {}", method, endpoint, &cats[..cats.len().min(256)]));
        } else {
            { let mut rc = self.violation_rate_computer.write(); rc.push((ep_key, 0.0)); }
        }

        ValidationResult { valid, violations, severity: max_sev }
    }

    pub fn validate(&self, method: &str, endpoint: &str, fields: &[&str]) -> bool {
        self.total_validated.fetch_add(1, Ordering::Relaxed);
        let key = format!("{}:{}", method, endpoint);
        if let Some(schema) = self.schemas.read().get(&key) {
            for req in &schema.required_fields {
                if !fields.contains(&req.as_str()) {
                    self.total_violations.fetch_add(1, Ordering::Relaxed);
                    let now = chrono::Utc::now().timestamp();
                    warn!(endpoint = %endpoint, field = %req, "Schema violation");
                    self.add_alert(now, Severity::High, "Schema violation", &format!("{} missing field {}", endpoint, req));
                    return false;
                }
            }
        }
        true
    }

    fn record_audit(&self, entry: &str) {
        let compressed = compression::compress_lz4(entry.as_bytes());
        let mut audit = self.compressed_audit.write();
        if audit.len() >= MAX_RECORDS { let half = audit.len() / 2; audit.drain(..half); }
        audit.push(compressed);
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(ApiAlert { timestamp: ts, severity: sev, component: "schema_validator".into(), title: title.into(), details: details.into() });
    }

    pub fn total_validated(&self) -> u64 { self.total_validated.load(Ordering::Relaxed) }
    pub fn total_violations(&self) -> u64 { self.total_violations.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<ApiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }

    pub fn report(&self) -> SchemaValidatorReport {
        let validated = self.total_validated.load(Ordering::Relaxed);
        let violations = self.total_violations.load(Ordering::Relaxed);
        let report = SchemaValidatorReport {
            total_validated: validated, total_violations: violations,
            violation_rate_pct: if validated == 0 { 0.0 } else { violations as f64 / validated as f64 * 100.0 },
            schemas_registered: self.schemas.read().len() as u64,
        };
        { let mut h = self.history.write(); h.checkpoint(ValidateWindowSummary { validated, violations }); }
        report
    }
}
