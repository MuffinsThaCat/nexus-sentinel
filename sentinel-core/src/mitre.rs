//! MITRE ATT&CK Framework Integration
//!
//! Provides standardized tactic/technique mappings, cross-correlation hooks,
//! and configurable detection thresholds for all Nexus Sentinel modules.
//!
//! This module elevates every security component to CrowdStrike-tier by ensuring:
//! 1. Every finding maps to a MITRE ATT&CK technique ID
//! 2. Findings can be cross-correlated across modules for kill-chain reconstruction
//! 3. Detection thresholds are configurable per-deployment, not hardcoded

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

// ─── MITRE ATT&CK Tactics ───────────────────────────────────────────────────

/// MITRE ATT&CK Tactic (kill-chain phase)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum MitreTactic {
    Reconnaissance,
    ResourceDevelopment,
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    CommandAndControl,
    Exfiltration,
    Impact,
}

impl MitreTactic {
    pub fn id(&self) -> &'static str {
        match self {
            Self::Reconnaissance => "TA0043",
            Self::ResourceDevelopment => "TA0042",
            Self::InitialAccess => "TA0001",
            Self::Execution => "TA0002",
            Self::Persistence => "TA0003",
            Self::PrivilegeEscalation => "TA0004",
            Self::DefenseEvasion => "TA0005",
            Self::CredentialAccess => "TA0006",
            Self::Discovery => "TA0007",
            Self::LateralMovement => "TA0008",
            Self::Collection => "TA0009",
            Self::CommandAndControl => "TA0011",
            Self::Exfiltration => "TA0010",
            Self::Impact => "TA0040",
        }
    }
}

// ─── MITRE ATT&CK Technique Mapping ────────────────────────────────────────

/// A mapping from a detection finding to MITRE ATT&CK technique(s).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TechniqueMapping {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: MitreTactic,
    pub sub_technique: Option<String>,
    pub data_sources: Vec<String>,
    pub platforms: Vec<String>,
}

/// Pre-built mapping database. Modules register their finding→technique mappings here.
pub struct MitreMapper {
    mappings: RwLock<HashMap<String, Vec<TechniqueMapping>>>,
    total_lookups: AtomicU64,
}

impl MitreMapper {
    pub fn new() -> Self {
        let mut m = HashMap::new();
        // ── Network module mappings ──
        Self::seed_network_mappings(&mut m);
        // ── Endpoint module mappings ──
        Self::seed_endpoint_mappings(&mut m);
        // ── Browser module mappings ──
        Self::seed_browser_mappings(&mut m);
        // ── Supply chain module mappings ──
        Self::seed_supply_chain_mappings(&mut m);
        // ── API module mappings ──
        Self::seed_api_mappings(&mut m);
        // ── Exfiltration module mappings ──
        Self::seed_exfiltration_mappings(&mut m);
        // ── Email module mappings ──
        Self::seed_email_mappings(&mut m);
        // ── Crypto module mappings ──
        Self::seed_crypto_mappings(&mut m);
        // ── Deception module mappings ──
        Self::seed_deception_mappings(&mut m);

        Self { mappings: RwLock::new(m), total_lookups: AtomicU64::new(0) }
    }

    /// Look up MITRE ATT&CK technique(s) for a finding category string.
    pub fn lookup(&self, finding: &str) -> Vec<TechniqueMapping> {
        self.total_lookups.fetch_add(1, Ordering::Relaxed);
        let map = self.mappings.read();
        // Exact match first
        if let Some(v) = map.get(finding) { return v.clone(); }
        // Prefix match (e.g., "xss_cookie_theft" matches "xss_")
        let mut results = Vec::new();
        for (key, val) in map.iter() {
            if finding.starts_with(key) || key.starts_with(finding) {
                results.extend(val.iter().cloned());
            }
        }
        results
    }

    /// Register a custom finding→technique mapping.
    pub fn register(&self, finding: String, mapping: TechniqueMapping) {
        self.mappings.write().entry(finding).or_default().push(mapping);
    }

    pub fn total_lookups(&self) -> u64 { self.total_lookups.load(Ordering::Relaxed) }

    fn tm(tid: &str, name: &str, tactic: MitreTactic, sub: Option<&str>, ds: &[&str], plat: &[&str]) -> TechniqueMapping {
        TechniqueMapping {
            technique_id: tid.into(), technique_name: name.into(), tactic,
            sub_technique: sub.map(|s| s.into()),
            data_sources: ds.iter().map(|s| s.to_string()).collect(),
            platforms: plat.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn seed_network_mappings(m: &mut HashMap<String, Vec<TechniqueMapping>>) {
        let all = &["Windows", "Linux", "macOS", "Network"];
        m.insert("port_scan".into(), vec![Self::tm("T1046", "Network Service Discovery", MitreTactic::Discovery, None, &["Network Traffic"], all)]);
        m.insert("syn_flood".into(), vec![Self::tm("T1498", "Network Denial of Service", MitreTactic::Impact, Some("T1498.001"), &["Network Traffic"], all)]);
        m.insert("arp_spoof".into(), vec![Self::tm("T1557", "Adversary-in-the-Middle", MitreTactic::CredentialAccess, Some("T1557.002"), &["Network Traffic"], all)]);
        m.insert("dns_tunnel".into(), vec![Self::tm("T1071", "Application Layer Protocol", MitreTactic::CommandAndControl, Some("T1071.004"), &["Network Traffic"], all)]);
        m.insert("c2_beacon".into(), vec![Self::tm("T1071", "Application Layer Protocol", MitreTactic::CommandAndControl, None, &["Network Traffic"], all)]);
        m.insert("lateral_movement".into(), vec![Self::tm("T1021", "Remote Services", MitreTactic::LateralMovement, None, &["Network Traffic"], all)]);
        m.insert("rate_limit_bypass".into(), vec![Self::tm("T1499", "Endpoint Denial of Service", MitreTactic::Impact, None, &["Network Traffic"], all)]);
        m.insert("geo_fence_violation".into(), vec![Self::tm("T1090", "Proxy", MitreTactic::CommandAndControl, Some("T1090.003"), &["Network Traffic"], all)]);
        m.insert("vpn_anomaly".into(), vec![Self::tm("T1133", "External Remote Services", MitreTactic::InitialAccess, None, &["Network Traffic"], all)]);
        m.insert("weak_cipher".into(), vec![Self::tm("T1573", "Encrypted Channel", MitreTactic::CommandAndControl, Some("T1573.001"), &["Network Traffic"], all)]);
        m.insert("cert_invalid".into(), vec![Self::tm("T1553", "Subvert Trust Controls", MitreTactic::DefenseEvasion, Some("T1553.004"), &["Network Traffic"], all)]);
    }

    fn seed_endpoint_mappings(m: &mut HashMap<String, Vec<TechniqueMapping>>) {
        let all = &["Windows", "Linux", "macOS"];
        m.insert("suspicious_process".into(), vec![Self::tm("T1059", "Command and Scripting Interpreter", MitreTactic::Execution, None, &["Process"], all)]);
        m.insert("privilege_escalation".into(), vec![Self::tm("T1068", "Exploitation for Privilege Escalation", MitreTactic::PrivilegeEscalation, None, &["Process"], all)]);
        m.insert("file_integrity_violation".into(), vec![Self::tm("T1565", "Data Manipulation", MitreTactic::Impact, Some("T1565.001"), &["File"], all)]);
        m.insert("usb_device".into(), vec![Self::tm("T1091", "Replication Through Removable Media", MitreTactic::LateralMovement, None, &["Drive"], all)]);
        m.insert("registry_modification".into(), vec![Self::tm("T1112", "Modify Registry", MitreTactic::DefenseEvasion, None, &["Windows Registry"], &["Windows"])]);
        m.insert("kernel_module".into(), vec![Self::tm("T1547", "Boot or Logon Autostart Execution", MitreTactic::Persistence, Some("T1547.006"), &["Kernel"], all)]);
        m.insert("unsigned_module".into(), vec![Self::tm("T1014", "Rootkit", MitreTactic::DefenseEvasion, None, &["Kernel"], all)]);
        m.insert("app_blocked".into(), vec![Self::tm("T1204", "User Execution", MitreTactic::Execution, None, &["Process"], all)]);
        m.insert("ransomware".into(), vec![Self::tm("T1486", "Data Encrypted for Impact", MitreTactic::Impact, None, &["File"], all)]);
    }

    fn seed_browser_mappings(m: &mut HashMap<String, Vec<TechniqueMapping>>) {
        let browser = &["Windows", "Linux", "macOS"];
        m.insert("xss_".into(), vec![Self::tm("T1189", "Drive-by Compromise", MitreTactic::InitialAccess, None, &["Application Log"], browser)]);
        m.insert("tracking_domain".into(), vec![Self::tm("T1185", "Browser Session Hijacking", MitreTactic::Collection, None, &["Web Credential"], browser)]);
        m.insert("supercookie".into(), vec![Self::tm("T1185", "Browser Session Hijacking", MitreTactic::Collection, None, &["Web Credential"], browser)]);
        m.insert("session_fixation".into(), vec![Self::tm("T1539", "Steal Web Session Cookie", MitreTactic::CredentialAccess, None, &["Web Credential"], browser)]);
        m.insert("malicious_extension".into(), vec![Self::tm("T1176", "Browser Extensions", MitreTactic::Persistence, None, &["Browser Extension"], browser)]);
        m.insert("cryptojacking".into(), vec![Self::tm("T1496", "Resource Hijacking", MitreTactic::Impact, None, &["Process"], browser)]);
        m.insert("keylogger".into(), vec![Self::tm("T1056", "Input Capture", MitreTactic::Collection, Some("T1056.001"), &["Application Log"], browser)]);
        m.insert("fingerprint_".into(), vec![Self::tm("T1217", "Browser Information Discovery", MitreTactic::Discovery, None, &["Application Log"], browser)]);
        m.insert("clickjack".into(), vec![Self::tm("T1189", "Drive-by Compromise", MitreTactic::InitialAccess, None, &["Application Log"], browser)]);
        m.insert("blocklisted".into(), vec![Self::tm("T1071", "Application Layer Protocol", MitreTactic::CommandAndControl, None, &["Network Traffic"], browser)]);
        m.insert("suspicious_tld".into(), vec![Self::tm("T1583", "Acquire Infrastructure", MitreTactic::ResourceDevelopment, Some("T1583.001"), &["Domain Name"], browser)]);
        m.insert("code_exec_eval".into(), vec![Self::tm("T1059", "Command and Scripting Interpreter", MitreTactic::Execution, Some("T1059.007"), &["Application Log"], browser)]);
        m.insert("obfuscation_".into(), vec![Self::tm("T1027", "Obfuscated Files or Information", MitreTactic::DefenseEvasion, None, &["Application Log"], browser)]);
        m.insert("exfil_".into(), vec![Self::tm("T1041", "Exfiltration Over C2 Channel", MitreTactic::Exfiltration, None, &["Network Traffic"], browser)]);
    }

    fn seed_supply_chain_mappings(m: &mut HashMap<String, Vec<TechniqueMapping>>) {
        let all = &["Windows", "Linux", "macOS"];
        m.insert("vulnerable_dependency".into(), vec![Self::tm("T1195", "Supply Chain Compromise", MitreTactic::InitialAccess, Some("T1195.001"), &["Application Log"], all)]);
        m.insert("typosquatting".into(), vec![Self::tm("T1195", "Supply Chain Compromise", MitreTactic::InitialAccess, Some("T1195.002"), &["Application Log"], all)]);
        m.insert("signature_invalid".into(), vec![Self::tm("T1553", "Subvert Trust Controls", MitreTactic::DefenseEvasion, Some("T1553.006"), &["File"], all)]);
        m.insert("build_tampering".into(), vec![Self::tm("T1195", "Supply Chain Compromise", MitreTactic::InitialAccess, Some("T1195.002"), &["Application Log"], all)]);
        m.insert("forbidden_license".into(), vec![Self::tm("T1195", "Supply Chain Compromise", MitreTactic::InitialAccess, None, &["Application Log"], all)]);
        m.insert("copyleft_propagation".into(), vec![Self::tm("T1195", "Supply Chain Compromise", MitreTactic::InitialAccess, None, &["Application Log"], all)]);
        m.insert("sbom_risk".into(), vec![Self::tm("T1195", "Supply Chain Compromise", MitreTactic::InitialAccess, None, &["Application Log"], all)]);
    }

    fn seed_api_mappings(m: &mut HashMap<String, Vec<TechniqueMapping>>) {
        let all = &["Windows", "Linux", "macOS", "SaaS"];
        m.insert("sqli".into(), vec![Self::tm("T1190", "Exploit Public-Facing Application", MitreTactic::InitialAccess, None, &["Application Log"], all)]);
        m.insert("xss".into(), vec![Self::tm("T1189", "Drive-by Compromise", MitreTactic::InitialAccess, None, &["Application Log"], all)]);
        m.insert("command_injection".into(), vec![Self::tm("T1059", "Command and Scripting Interpreter", MitreTactic::Execution, None, &["Application Log"], all)]);
        m.insert("path_traversal".into(), vec![Self::tm("T1083", "File and Directory Discovery", MitreTactic::Discovery, None, &["Application Log"], all)]);
        m.insert("ssrf".into(), vec![Self::tm("T1090", "Proxy", MitreTactic::CommandAndControl, None, &["Application Log"], all)]);
        m.insert("schema_violation".into(), vec![Self::tm("T1190", "Exploit Public-Facing Application", MitreTactic::InitialAccess, None, &["Application Log"], all)]);
    }

    fn seed_exfiltration_mappings(m: &mut HashMap<String, Vec<TechniqueMapping>>) {
        let all = &["Windows", "Linux", "macOS"];
        m.insert("dns_exfil".into(), vec![Self::tm("T1048", "Exfiltration Over Alternative Protocol", MitreTactic::Exfiltration, Some("T1048.003"), &["Network Traffic"], all)]);
        m.insert("icmp_exfil".into(), vec![Self::tm("T1048", "Exfiltration Over Alternative Protocol", MitreTactic::Exfiltration, Some("T1048.003"), &["Network Traffic"], all)]);
        m.insert("http_exfil".into(), vec![Self::tm("T1041", "Exfiltration Over C2 Channel", MitreTactic::Exfiltration, None, &["Network Traffic"], all)]);
        m.insert("stego_exfil".into(), vec![Self::tm("T1027", "Obfuscated Files or Information", MitreTactic::DefenseEvasion, Some("T1027.003"), &["File"], all)]);
    }

    fn seed_email_mappings(m: &mut HashMap<String, Vec<TechniqueMapping>>) {
        let all = &["Windows", "Linux", "macOS", "SaaS"];
        m.insert("spam".into(), vec![Self::tm("T1566", "Phishing", MitreTactic::InitialAccess, Some("T1566.001"), &["Application Log"], all)]);
        m.insert("spf_fail".into(), vec![Self::tm("T1566", "Phishing", MitreTactic::InitialAccess, Some("T1566.002"), &["Application Log"], all)]);
        m.insert("dkim_fail".into(), vec![Self::tm("T1566", "Phishing", MitreTactic::InitialAccess, None, &["Application Log"], all)]);
    }

    fn seed_crypto_mappings(m: &mut HashMap<String, Vec<TechniqueMapping>>) {
        let all = &["Windows", "Linux", "macOS"];
        m.insert("weak_tls".into(), vec![Self::tm("T1557", "Adversary-in-the-Middle", MitreTactic::CredentialAccess, None, &["Network Traffic"], all)]);
        m.insert("expired_cert".into(), vec![Self::tm("T1553", "Subvert Trust Controls", MitreTactic::DefenseEvasion, Some("T1553.004"), &["File"], all)]);
        m.insert("untrusted_ca".into(), vec![Self::tm("T1553", "Subvert Trust Controls", MitreTactic::DefenseEvasion, Some("T1553.004"), &["File"], all)]);
    }

    fn seed_deception_mappings(m: &mut HashMap<String, Vec<TechniqueMapping>>) {
        let all = &["Windows", "Linux", "macOS"];
        m.insert("honeypot_triggered".into(), vec![Self::tm("T1018", "Remote System Discovery", MitreTactic::Discovery, None, &["Network Traffic"], all)]);
        m.insert("honey_token_accessed".into(), vec![Self::tm("T1083", "File and Directory Discovery", MitreTactic::Discovery, None, &["File"], all)]);
        m.insert("attacker_recon".into(), vec![Self::tm("T1595", "Active Scanning", MitreTactic::Reconnaissance, None, &["Network Traffic"], all)]);
    }
}

// ─── Cross-Correlation Engine ───────────────────────────────────────────────

/// A correlated finding that links detections across modules into kill-chain stages.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CorrelatedFinding {
    pub id: u64,
    pub timestamp: i64,
    pub source_module: String,
    pub finding: String,
    pub mitre_technique: String,
    pub mitre_tactic: MitreTactic,
    pub severity_score: f64,
    pub entity: String, // IP, user, host, domain, etc.
}

/// Cross-correlation engine that receives findings from all modules and
/// detects multi-stage attack patterns (kill-chain reconstruction).
pub struct CrossCorrelator {
    findings: RwLock<Vec<CorrelatedFinding>>,
    entity_tactic_counts: RwLock<HashMap<String, HashMap<MitreTactic, u64>>>,
    next_id: AtomicU64,
    kill_chain_threshold: RwLock<u32>,
    max_findings: usize,
}

impl CrossCorrelator {
    pub fn new() -> Self {
        Self {
            findings: RwLock::new(Vec::new()),
            entity_tactic_counts: RwLock::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            kill_chain_threshold: RwLock::new(3), // Alert when entity hits 3+ tactics
            max_findings: 100_000,
        }
    }

    /// Ingest a finding from any module. Returns true if this triggers a kill-chain alert.
    pub fn ingest(&self, source_module: &str, finding: &str, tactic: MitreTactic,
                  technique_id: &str, severity: f64, entity: &str) -> bool {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();

        let cf = CorrelatedFinding {
            id, timestamp: now, source_module: source_module.into(),
            finding: finding.into(), mitre_technique: technique_id.into(),
            mitre_tactic: tactic, severity_score: severity, entity: entity.into(),
        };

        // Store finding
        {
            let mut f = self.findings.write();
            if f.len() >= self.max_findings { let half = f.len() / 2; f.drain(..half); }
            f.push(cf);
        }

        // Update entity→tactic counts
        let mut etc = self.entity_tactic_counts.write();
        let entity_tactics = etc.entry(entity.into()).or_default();
        *entity_tactics.entry(tactic).or_insert(0) += 1;
        let distinct_tactics = entity_tactics.len() as u32;
        let threshold = *self.kill_chain_threshold.read();

        distinct_tactics >= threshold
    }

    /// Get all distinct tactics observed for an entity.
    pub fn entity_tactics(&self, entity: &str) -> Vec<(MitreTactic, u64)> {
        let etc = self.entity_tactic_counts.read();
        etc.get(entity).map(|m| m.iter().map(|(t, c)| (*t, *c)).collect()).unwrap_or_default()
    }

    /// Get recent findings for an entity (last N).
    pub fn entity_findings(&self, entity: &str, limit: usize) -> Vec<CorrelatedFinding> {
        let f = self.findings.read();
        f.iter().rev().filter(|cf| cf.entity == entity).take(limit).cloned().collect()
    }

    /// Set the kill-chain alert threshold (distinct tactics before alerting).
    pub fn set_kill_chain_threshold(&self, threshold: u32) {
        *self.kill_chain_threshold.write() = threshold;
    }

    pub fn total_findings(&self) -> usize { self.findings.read().len() }
}

// ─── Configurable Detection Thresholds ──────────────────────────────────────

/// Per-module configurable thresholds. Modules query this at runtime instead
/// of using hardcoded constants.
pub struct DetectionThresholds {
    thresholds: RwLock<HashMap<String, f64>>,
}

impl DetectionThresholds {
    pub fn new() -> Self {
        let mut t = HashMap::new();
        // Network defaults
        t.insert("network.port_scan.min_ports".into(), 50.0);
        t.insert("network.syn_flood.pps_threshold".into(), 10_000.0);
        t.insert("network.arp_spoof.max_changes_per_min".into(), 5.0);
        t.insert("network.bandwidth.spike_multiplier".into(), 3.0);
        t.insert("network.geo_fence.max_distance_km".into(), 1000.0);
        t.insert("network.rate_limit.burst_multiplier".into(), 10.0);
        // Endpoint defaults
        t.insert("endpoint.process.cpu_threshold_pct".into(), 90.0);
        t.insert("endpoint.file_integrity.max_changes_per_min".into(), 100.0);
        t.insert("endpoint.privilege.escalation_window_secs".into(), 300.0);
        t.insert("endpoint.ransomware.entropy_threshold".into(), 7.5);
        // Browser defaults
        t.insert("browser.cookie.max_lifetime_days".into(), 365.0);
        t.insert("browser.extension.max_dangerous_perms".into(), 5.0);
        t.insert("browser.script.max_avg_line_length".into(), 5000.0);
        t.insert("browser.url.max_subdomain_levels".into(), 4.0);
        // Supply chain defaults
        t.insert("supply_chain.dependency.max_vuln_age_days".into(), 90.0);
        t.insert("supply_chain.sbom.staleness_days".into(), 90.0);
        t.insert("supply_chain.sbom.risk_alert_threshold".into(), 0.3);
        // API defaults
        t.insert("api.rate_limit.window_secs".into(), 60.0);
        t.insert("api.payload.max_size_bytes".into(), 1_048_576.0);
        t.insert("api.schema.max_field_length".into(), 10_000.0);
        // Exfiltration defaults
        t.insert("exfil.dns.max_query_length".into(), 100.0);
        t.insert("exfil.volume.daily_limit_mb".into(), 500.0);
        // Email defaults
        t.insert("email.spam.keyword_threshold".into(), 3.0);
        t.insert("email.spam.burst_window_secs".into(), 60.0);
        // Crypto defaults
        t.insert("crypto.tls.min_version".into(), 1.2);
        t.insert("crypto.cert.warn_days_before_expiry".into(), 30.0);
        // General
        t.insert("general.alert_cap".into(), 5000.0);
        t.insert("general.audit_cap".into(), 10000.0);

        Self { thresholds: RwLock::new(t) }
    }

    /// Get a threshold value. Returns the default if not overridden.
    pub fn get(&self, key: &str) -> f64 {
        *self.thresholds.read().get(key).unwrap_or(&0.0)
    }

    /// Get with a fallback default.
    pub fn get_or(&self, key: &str, default: f64) -> f64 {
        *self.thresholds.read().get(key).unwrap_or(&default)
    }

    /// Override a threshold at runtime.
    pub fn set(&self, key: &str, value: f64) {
        self.thresholds.write().insert(key.into(), value);
    }

    /// Bulk-set from a HashMap (e.g., loaded from config file).
    pub fn load_overrides(&self, overrides: &HashMap<String, f64>) {
        let mut t = self.thresholds.write();
        for (k, v) in overrides { t.insert(k.clone(), *v); }
    }

    /// List all configured keys.
    pub fn keys(&self) -> Vec<String> {
        self.thresholds.read().keys().cloned().collect()
    }
}

// ─── Global Singleton Accessors ─────────────────────────────────────────────

use std::sync::OnceLock;

static MITRE_MAPPER: OnceLock<MitreMapper> = OnceLock::new();
static CROSS_CORRELATOR: OnceLock<CrossCorrelator> = OnceLock::new();
static DETECTION_THRESHOLDS: OnceLock<DetectionThresholds> = OnceLock::new();

/// Get the global MITRE ATT&CK mapper.
pub fn mitre_mapper() -> &'static MitreMapper {
    MITRE_MAPPER.get_or_init(MitreMapper::new)
}

/// Get the global cross-correlation engine.
pub fn correlator() -> &'static CrossCorrelator {
    CROSS_CORRELATOR.get_or_init(CrossCorrelator::new)
}

/// Get the global configurable thresholds.
pub fn thresholds() -> &'static DetectionThresholds {
    DETECTION_THRESHOLDS.get_or_init(DetectionThresholds::new)
}

/// Universal auto-correlate: given a module name, finding string, severity (0.0–1.0),
/// and entity, automatically looks up MITRE techniques and feeds the correlator.
/// Returns true if this triggered a kill-chain alert.
///
/// This is the single-line integration point that every module can call.
pub fn auto_correlate(module: &str, finding: &str, severity: f64, entity: &str) -> bool {
    let techniques = mitre_mapper().lookup(finding);
    let mut triggered = false;
    for tech in &techniques {
        if correlator().ingest(module, finding, tech.tactic, &tech.technique_id, severity, entity) {
            triggered = true;
        }
    }
    // If no exact technique match, still feed the correlator with a generic tactic
    // derived from the module name for kill-chain tracking
    if techniques.is_empty() {
        let tactic = match module {
            m if m.contains("network") || m.contains("firewall") || m.contains("arp") || m.contains("vpn") => MitreTactic::CommandAndControl,
            m if m.contains("endpoint") || m.contains("process") || m.contains("kernel") => MitreTactic::Execution,
            m if m.contains("exfil") || m.contains("dlp") => MitreTactic::Exfiltration,
            m if m.contains("browser") || m.contains("cookie") || m.contains("script") => MitreTactic::InitialAccess,
            m if m.contains("supply") || m.contains("artifact") || m.contains("dependency") => MitreTactic::InitialAccess,
            m if m.contains("crypto") || m.contains("tls") || m.contains("cert") => MitreTactic::CredentialAccess,
            m if m.contains("email") || m.contains("spam") || m.contains("phishing") => MitreTactic::InitialAccess,
            m if m.contains("identity") || m.contains("auth") || m.contains("credential") => MitreTactic::CredentialAccess,
            m if m.contains("deception") || m.contains("honey") => MitreTactic::Discovery,
            m if m.contains("privacy") || m.contains("dsar") => MitreTactic::Collection,
            _ => MitreTactic::Impact,
        };
        if correlator().ingest(module, finding, tactic, "T0000", severity, entity) {
            triggered = true;
        }
    }
    triggered
}
