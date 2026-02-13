use serde::{Serialize, Deserialize};
use std::sync::Arc;
use sysinfo::{System, Pid};
use parking_lot::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Tier { Free, Pro, Enterprise }

impl Tier {
    pub fn label(&self) -> &'static str { match self { Tier::Free => "Community Shield", Tier::Pro => "Pro", Tier::Enterprise => "Enterprise" } }
    pub fn price(&self) -> &'static str { match self { Tier::Free => "$0", Tier::Pro => "$29/user/mo", Tier::Enterprise => "$99/user/mo" } }
}

pub fn domain_tier(domain: &str) -> Tier {
    match domain {
        // Free: 11 domains, 133 modules (includes 55-module AI Agent Security)
        "network" | "endpoint" | "dns" | "email" | "browser"
        | "phishing" | "privacy" | "selfprotect" | "vpn" | "vuln"
        | "ai" => Tier::Free,
        // Pro: +11 domains (22 total), 202 modules
        "identity" | "siem" | "cloud" | "container" | "supply_chain"
        | "data" | "api" | "web" | "exfiltration" | "mgmt"
        | "malware" => Tier::Pro,
        // Enterprise: +17 domains (38 total), 291 modules
        _ => Tier::Enterprise,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DomainStatus { pub domain: String, pub display_name: String, pub enabled: bool, pub module_count: usize, pub tier: Tier }
#[derive(Debug, Clone, Serialize)]
pub struct UnifiedAlert { pub timestamp: i64, pub severity: String, pub domain: String, pub component: String, pub title: String, pub details: String, pub remediation: Option<String> }
#[derive(Debug, Clone, Serialize)]
pub struct StatusResponse { pub domains: Vec<DomainStatus>, pub enabled_domains: usize, pub total_modules: usize, pub uptime_secs: i64, pub current_tier: Tier }
#[derive(Debug, Clone, Serialize)]
pub struct AlertResponse { pub alerts: Vec<UnifiedAlert>, pub total: usize, pub critical: usize, pub high: usize }
#[derive(Debug, Clone, Serialize)]
pub struct MetricsResponse { pub total_budget: usize, pub total_used: usize, pub utilization_percent: f64, pub process_rss: u64, pub process_vms: u64 }
#[derive(Debug, Clone, Serialize)]
pub struct TierInfo {
    pub current: Tier,
    pub tiers: Vec<TierDetail>,
}
#[derive(Debug, Clone, Serialize)]
pub struct TierDetail {
    pub tier: Tier,
    pub name: String,
    pub price: String,
    pub domains: usize,
    pub modules: usize,
    pub features: Vec<String>,
}

struct AlertSource { _domain: String, _name: String, get_alerts: Box<dyn Fn() -> Vec<UnifiedAlert> + Send + Sync> }

macro_rules! reg {
    ($s:expr, $d:expr, $n:expr, $mod:expr) => {{
        let a = Arc::new($mod); let r = a.clone();
        $s.push(AlertSource { _domain: $d.into(), _name: $n.into(),
            get_alerts: Box::new(move || {
                r.alerts().into_iter().map(|a| UnifiedAlert {
                    timestamp: a.timestamp, severity: format!("{:?}", a.severity),
                    domain: $d.into(), component: a.component, title: a.title, details: a.details,
                    remediation: None,
                }).collect()
            }),
        });
    }};
}
macro_rules! noa { ($k:expr, $mod:expr) => { $k.push(Box::new($mod) as Box<dyn std::any::Any + Send + Sync>); }; }
macro_rules! dom { ($v:expr, $d:expr, $dn:expr, $c:expr) => { $v.push(DomainStatus { domain: $d.into(), display_name: $dn.into(), enabled: true, module_count: $c, tier: domain_tier($d) }); }; }

pub struct SentinelBackend {
    domains: Vec<DomainStatus>,
    alert_sources: Vec<AlertSource>,
    _kept: Vec<Box<dyn std::any::Any + Send + Sync>>,
    metrics: sentinel_core::MemoryMetrics,
    start_time: i64,
    pub current_tier: RwLock<Tier>,
}
unsafe impl Send for SentinelBackend {}
unsafe impl Sync for SentinelBackend {}

impl SentinelBackend {
    pub fn new() -> Self {
        let metrics = sentinel_core::MemoryMetrics::new(512 * 1024 * 1024);
        let m = metrics.clone();
        let mut d = Vec::new(); let mut s: Vec<AlertSource> = Vec::new();
        let mut k: Vec<Box<dyn std::any::Any + Send + Sync>> = Vec::new();
        bootstrap_all(&mut d, &mut s, &mut k, m);
        let total: usize = d.iter().map(|x| x.module_count).sum();
        log::info!("Beaver Warrior: {} domains, {} modules loaded", d.len(), total);
        SentinelBackend { domains: d, alert_sources: s, _kept: k, metrics, start_time: chrono::Utc::now().timestamp(), current_tier: RwLock::new(Tier::Free) }
    }
    fn collect_alerts(&self) -> Vec<UnifiedAlert> {
        let mut all = Vec::new();
        for src in &self.alert_sources { all.extend((src.get_alerts)()); }
        // Startup alert so users know protection is active
        let total: usize = self.domains.iter().map(|x| x.module_count).sum();
        all.push(UnifiedAlert {
            timestamp: self.start_time,
            severity: "Info".into(),
            domain: "system".into(),
            component: "Beaver Warrior".into(),
            title: format!("Protection active — {} modules across {} domains", total, self.domains.len()),
            details: "All security modules are running locally on your machine. No data leaves your device.".into(),
            remediation: None,
        });
        all.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        all.truncate(500); all
    }
}

fn bootstrap_all(d: &mut Vec<DomainStatus>, s: &mut Vec<AlertSource>, k: &mut Vec<Box<dyn std::any::Any + Send + Sync>>, m: sentinel_core::MemoryMetrics) {
    // ── 1. Network (15 modules) ──
    { use sentinel_network::firewall::Firewall;
      use sentinel_network::ids::{IntrusionDetector, IdsMode};
      use sentinel_network::flow_monitor::FlowMonitor;
      use sentinel_network::arp_guard::ArpGuard;
      use sentinel_network::port_scanner_detect::PortScanDetector;
      use sentinel_network::bandwidth_monitor::BandwidthMonitor;
      use sentinel_network::cert_validator::CertValidator;
      use sentinel_network::connection_tracker::ConnectionTracker;
      use sentinel_network::geo_fence::GeoFence;
      use sentinel_network::net_anomaly::NetAnomalyDetector;
      use sentinel_network::packet_capture::PacketCapture;
      use sentinel_network::protocol_analyzer::ProtocolAnalyzer;
      use sentinel_network::rate_limiter::RateLimiter;
      use sentinel_network::traffic_shaper::TrafficShaper;
      use sentinel_network::vpn_monitor::VpnMonitor;
      // Firewall — adapt sentinel_network::types::Alert → UnifiedAlert
      { let fw = Arc::new(Firewall::new().with_metrics(m.clone())); let r = fw.clone();
        s.push(AlertSource { _domain: "network".into(), _name: "Firewall".into(),
            get_alerts: Box::new(move || {
                r.alerts().into_iter().map(|a| UnifiedAlert {
                    timestamp: a.timestamp, severity: format!("{:?}", a.severity),
                    domain: "network".into(), component: "Firewall".into(),
                    title: a.rule_name.clone(),
                    details: format!("{} | {}:{} → {}:{}", a.message, a.src_ip, a.src_port, a.dst_ip, a.dst_port),
                    remediation: None,
                }).collect()
            }),
        }); k.push(Box::new(fw)); }
      // IDS — adapt recent_alerts() → UnifiedAlert
      { let ids = Arc::new(IntrusionDetector::new(IdsMode::Detection).with_metrics(m.clone())); let r = ids.clone();
        s.push(AlertSource { _domain: "network".into(), _name: "IDS".into(),
            get_alerts: Box::new(move || {
                r.recent_alerts().into_iter().map(|a| UnifiedAlert {
                    timestamp: a.timestamp, severity: format!("{:?}", a.severity),
                    domain: "network".into(), component: "IDS".into(),
                    title: a.rule_name.clone(),
                    details: format!("{} | {}:{} → {}:{}", a.message, a.src_ip, a.src_port, a.dst_ip, a.dst_port),
                    remediation: None,
                }).collect()
            }),
        }); k.push(Box::new(ids)); }
      // ARP Guard — adapt ArpSpoofAlert → UnifiedAlert
      { let arp = Arc::new(ArpGuard::new().with_metrics(m.clone())); let r = arp.clone();
        s.push(AlertSource { _domain: "network".into(), _name: "ARP Guard".into(),
            get_alerts: Box::new(move || {
                r.alerts().into_iter().map(|a| UnifiedAlert {
                    timestamp: a.timestamp, severity: format!("{:?}", a.severity),
                    domain: "network".into(), component: "ARP Guard".into(),
                    title: format!("{:?} on {}", a.alert_type, a.ip),
                    details: format!("{} | expected={} observed={} conf={:.0}%", a.details, a.expected_mac, a.observed_mac, a.confidence * 100.0),
                    remediation: None,
                }).collect()
            }),
        }); k.push(Box::new(arp)); }
      // Infrastructure modules (no alert feeds)
      noa!(k, FlowMonitor::new(1000).with_metrics(m.clone()));
      noa!(k, PortScanDetector::new().with_metrics(m.clone()));
      noa!(k, BandwidthMonitor::new(1_000_000_000).with_metrics(m.clone()));
      noa!(k, CertValidator::new().with_metrics(m.clone()));
      noa!(k, ConnectionTracker::new(10000).with_metrics(m.clone()));
      noa!(k, GeoFence::new().with_metrics(m.clone()));
      noa!(k, NetAnomalyDetector::new(2.0).with_metrics(m.clone()));
      noa!(k, PacketCapture::new(10000, 256).with_metrics(m.clone()));
      noa!(k, ProtocolAnalyzer::new().with_metrics(m.clone()));
      noa!(k, RateLimiter::new(1000.0, 100.0, 10000).with_metrics(m.clone()));
      noa!(k, TrafficShaper::new().with_metrics(m.clone()));
      noa!(k, VpnMonitor::new().with_metrics(m.clone()));
      dom!(d, "network", "Network Security", 15); }

    // ── 2. Endpoint (12 modules) ──
    { use sentinel_endpoint::usb_guard::UsbGuard;
      use sentinel_endpoint::ransomware_detect::RansomwareDetector;
      use sentinel_endpoint::clipboard_monitor::ClipboardMonitor;
      use sentinel_endpoint::file_integrity::FileIntegrityMonitor;
      use sentinel_endpoint::kernel_monitor::KernelMonitor;
      use sentinel_endpoint::login_monitor::LoginMonitor;
      use sentinel_endpoint::privilege_monitor::PrivilegeMonitor;
      use sentinel_endpoint::process_monitor::ProcessMonitor;
      use sentinel_endpoint::registry_monitor::RegistryMonitor;
      use sentinel_endpoint::scheduled_task_monitor::ScheduledTaskMonitor;
      use sentinel_endpoint::screen_lock::ScreenLockMonitor;
      use sentinel_endpoint::app_control::AppControl;
      reg!(s, "endpoint", "USB Guard", UsbGuard::new().with_metrics(m.clone()));
      reg!(s, "endpoint", "Ransomware Detector", RansomwareDetector::new().with_metrics(m.clone()));
      reg!(s, "endpoint", "Clipboard Monitor", ClipboardMonitor::new().with_metrics(m.clone()));
      reg!(s, "endpoint", "File Integrity", FileIntegrityMonitor::new().with_metrics(m.clone()));
      reg!(s, "endpoint", "Kernel Monitor", KernelMonitor::new().with_metrics(m.clone()));
      reg!(s, "endpoint", "Login Monitor", LoginMonitor::new().with_metrics(m.clone()));
      reg!(s, "endpoint", "Privilege Monitor", PrivilegeMonitor::new().with_metrics(m.clone()));
      reg!(s, "endpoint", "Process Monitor", ProcessMonitor::new().with_metrics(m.clone()));
      reg!(s, "endpoint", "Registry Monitor", RegistryMonitor::new().with_metrics(m.clone()));
      reg!(s, "endpoint", "Scheduled Tasks", ScheduledTaskMonitor::new().with_metrics(m.clone()));
      reg!(s, "endpoint", "Screen Lock", ScreenLockMonitor::new(300).with_metrics(m.clone()));
      reg!(s, "endpoint", "App Control", AppControl::new(sentinel_endpoint::app_control::PolicyMode::Allowlist).with_metrics(m.clone()));
      dom!(d, "endpoint", "Endpoint Protection", 12); }

    // ── 2b. Malware Scanner + Download Guard — Pro (2 modules, 22 internal engines) ──
    { use sentinel_endpoint::malware_scanner::MalwareScanner;
      use sentinel_endpoint::download_guard::DownloadGuard;
      noa!(k, MalwareScanner::new());
      reg!(s, "malware", "Download Guard", DownloadGuard::new());
      dom!(d, "malware", "Malware Scanner", 2); }

    // ── 3. DNS (10 modules) ──
    { use sentinel_dns::dns_filter::DnsFilter;
      use sentinel_dns::dns_sinkhole::DnsSinkhole;
      use sentinel_dns::dns_tunnel_detect::DnsTunnelDetector;
      use sentinel_dns::dns_blocklist::DnsBlocklist;
      use sentinel_dns::dns_rate_limiter::DnsRateLimiter;
      use sentinel_dns::dns_rebind_protect::DnsRebindProtect;
      use sentinel_dns::dnssec_validator::DnssecValidator;
      use sentinel_dns::doh_proxy::DohProxy;
      use sentinel_dns::dns_cache::DnsCache;
      use sentinel_dns::dns_logging::DnsLogger;
      reg!(s, "dns", "DNS Filter", DnsFilter::new().with_metrics(m.clone()));
      reg!(s, "dns", "DNS Sinkhole", DnsSinkhole::new("0.0.0.0").with_metrics(m.clone()));
      reg!(s, "dns", "Tunnel Detector", DnsTunnelDetector::new().with_metrics(m.clone()));
      reg!(s, "dns", "DNS Blocklist", DnsBlocklist::new().with_metrics(m.clone()));
      reg!(s, "dns", "DNS Rate Limiter", DnsRateLimiter::new(100, 60).with_metrics(m.clone()));
      reg!(s, "dns", "Rebind Protect", DnsRebindProtect::new().with_metrics(m.clone()));
      reg!(s, "dns", "DNSSEC Validator", DnssecValidator::new(true).with_metrics(m.clone()));
      reg!(s, "dns", "DoH Proxy", DohProxy::new(false).with_metrics(m.clone()));
      noa!(k, DnsCache::new(10000).with_metrics(m.clone()));
      noa!(k, DnsLogger::new(10000).with_metrics(m.clone()));
      dom!(d, "dns", "DNS Security", 10); }

    // ── 4. Email (12 modules) ──
    { use sentinel_email::spam_filter::SpamFilter;
      use sentinel_email::attachment_scanner::AttachmentScanner;
      use sentinel_email::dkim_validator::DkimValidator;
      use sentinel_email::dlp_scanner::DlpScanner as EmailDlpScanner;
      use sentinel_email::dmarc_enforcer::DmarcEnforcer;
      use sentinel_email::email_encrypt::EmailEncrypt;
      use sentinel_email::email_rate_limiter::EmailRateLimiter;
      use sentinel_email::header_analyzer::HeaderAnalyzer;
      use sentinel_email::link_analyzer::LinkAnalyzer;
      use sentinel_email::phishing_detect::PhishingDetector;
      use sentinel_email::quarantine::QuarantineManager;
      use sentinel_email::spf_checker::SpfChecker;
      reg!(s, "email", "Spam Filter", SpamFilter::new(0.7).with_metrics(m.clone()));
      reg!(s, "email", "Attachment Scanner", AttachmentScanner::new().with_metrics(m.clone()));
      reg!(s, "email", "DKIM Validator", DkimValidator::new().with_metrics(m.clone()));
      reg!(s, "email", "Email DLP", EmailDlpScanner::new().with_metrics(m.clone()));
      reg!(s, "email", "DMARC Enforcer", DmarcEnforcer::new().with_metrics(m.clone()));
      reg!(s, "email", "Email Encrypt", EmailEncrypt::new().with_metrics(m.clone()));
      reg!(s, "email", "Rate Limiter", EmailRateLimiter::new(100, 60).with_metrics(m.clone()));
      reg!(s, "email", "Header Analyzer", HeaderAnalyzer::new().with_metrics(m.clone()));
      reg!(s, "email", "Link Analyzer", LinkAnalyzer::new().with_metrics(m.clone()));
      reg!(s, "email", "Phishing Detect", PhishingDetector::new().with_metrics(m.clone()));
      reg!(s, "email", "Quarantine", QuarantineManager::new().with_metrics(m.clone()));
      reg!(s, "email", "SPF Checker", SpfChecker::new().with_metrics(m.clone()));
      dom!(d, "email", "Email Security", 12); }

    // ── 5. Identity (9 modules) ──
    { use sentinel_identity::auth_manager::AuthManager;
      use sentinel_identity::session_manager::SessionManager;
      use sentinel_identity::mfa_engine::MfaEngine;
      use sentinel_identity::rbac_engine::RbacEngine;
      use sentinel_identity::credential_store::CredentialStore;
      use sentinel_identity::identity_federation::IdentityFederation;
      use sentinel_identity::privilege_access::PrivilegeAccessManager;
      use sentinel_identity::sso_provider::SsoManager;
      use sentinel_identity::user_behavior::UserBehaviorAnalytics;
      reg!(s, "identity", "Auth Manager", AuthManager::new(5, 900).with_metrics(m.clone()));
      reg!(s, "identity", "Session Manager", SessionManager::new(100, 3600).with_metrics(m.clone()));
      reg!(s, "identity", "MFA Engine", MfaEngine::new().with_metrics(m.clone()));
      reg!(s, "identity", "RBAC Engine", RbacEngine::new().with_metrics(m.clone()));
      reg!(s, "identity", "Credential Store", CredentialStore::new(90).with_metrics(m.clone()));
      reg!(s, "identity", "Identity Federation", IdentityFederation::new().with_metrics(m.clone()));
      reg!(s, "identity", "Privilege Access", PrivilegeAccessManager::new(3600).with_metrics(m.clone()));
      reg!(s, "identity", "SSO Provider", SsoManager::new().with_metrics(m.clone()));
      reg!(s, "identity", "User Behavior", UserBehaviorAnalytics::new(0.8).with_metrics(m.clone()));
      dom!(d, "identity", "Identity & Access", 9); }

    // ── 6. SIEM (10 modules) ──
    { use sentinel_siem::correlation_engine::CorrelationEngine;
      use sentinel_siem::alert_manager::AlertManager;
      use sentinel_siem::audit_trail::AuditTrail;
      use sentinel_siem::compliance_logger::ComplianceLogger;
      use sentinel_siem::dashboard_data::DashboardData;
      use sentinel_siem::log_collector::LogCollector;
      use sentinel_siem::log_forwarder::LogForwarder;
      use sentinel_siem::log_parser::LogParser;
      use sentinel_siem::log_storage::LogStorage;
      use sentinel_siem::report_generator::ReportGenerator as SiemReportGenerator;
      // Correlation Engine — adapt SiemAlert → UnifiedAlert
      { let ce = Arc::new(CorrelationEngine::new().with_metrics(m.clone())); let r = ce.clone();
        s.push(AlertSource { _domain: "siem".into(), _name: "Correlation Engine".into(),
            get_alerts: Box::new(move || {
                r.alerts().into_iter().map(|a| UnifiedAlert {
                    timestamp: a.timestamp, severity: format!("{:?}", a.severity),
                    domain: "siem".into(), component: "Correlation Engine".into(),
                    title: a.title,
                    details: format!("{} | rule={} events={}", a.details, a.rule_name, a.source_events.len()),
                    remediation: None,
                }).collect()
            }),
        }); k.push(Box::new(ce)); }
      // Infrastructure modules (no alert feeds)
      noa!(k, AlertManager::new(10000).with_metrics(m.clone()));
      noa!(k, AuditTrail::new(10000).with_metrics(m.clone()));
      noa!(k, ComplianceLogger::new(10000).with_metrics(m.clone()));
      noa!(k, DashboardData::new().with_metrics(m.clone()));
      noa!(k, LogCollector::new(10000).with_metrics(m.clone()));
      noa!(k, LogForwarder::new(5000).with_metrics(m.clone()));
      noa!(k, LogParser::new().with_metrics(m.clone()));
      noa!(k, LogStorage::new(100000, 86400 * 30).with_metrics(m.clone()));
      noa!(k, SiemReportGenerator::new(1000).with_metrics(m.clone()));
      dom!(d, "siem", "SIEM", 10); }

    // ── 7. IoT (9 modules) ──
    { use sentinel_iot::device_registry::DeviceRegistry;
      use sentinel_iot::anomaly_detector::AnomalyDetector;
      use sentinel_iot::device_auth::DeviceAuth;
      use sentinel_iot::device_policy::DevicePolicyEngine;
      use sentinel_iot::firmware_validator::FirmwareValidator;
      use sentinel_iot::network_segmenter::NetworkSegmenter;
      use sentinel_iot::ota_manager::OtaManager;
      use sentinel_iot::protocol_analyzer::ProtocolAnalyzer as IotProtocolAnalyzer;
      use sentinel_iot::telemetry_monitor::TelemetryMonitor;
      reg!(s, "iot", "Device Registry", DeviceRegistry::new().with_metrics(m.clone()));
      reg!(s, "iot", "Anomaly Detector", AnomalyDetector::new(0.8).with_metrics(m.clone()));
      reg!(s, "iot", "Device Auth", DeviceAuth::new().with_metrics(m.clone()));
      reg!(s, "iot", "Device Policy", DevicePolicyEngine::new().with_metrics(m.clone()));
      reg!(s, "iot", "Firmware Validator", FirmwareValidator::new().with_metrics(m.clone()));
      reg!(s, "iot", "Network Segmenter", NetworkSegmenter::new().with_metrics(m.clone()));
      reg!(s, "iot", "OTA Manager", OtaManager::new().with_metrics(m.clone()));
      reg!(s, "iot", "Protocol Analyzer", IotProtocolAnalyzer::new().with_metrics(m.clone()));
      reg!(s, "iot", "Telemetry Monitor", TelemetryMonitor::new().with_metrics(m.clone()));
      dom!(d, "iot", "IoT Security", 9); }

    // ── 8. Data Protection (9 modules) ──
    { use sentinel_data::tokenizer::Tokenizer;
      use sentinel_data::dlp_scanner::DlpScanner;
      use sentinel_data::access_controller::AccessController;
      use sentinel_data::backup_manager::BackupManager;
      use sentinel_data::classification_engine::ClassificationEngine;
      use sentinel_data::encryption_engine::EncryptionEngine;
      use sentinel_data::integrity_checker::IntegrityChecker;
      use sentinel_data::key_manager::KeyManager;
      use sentinel_data::masking_engine::MaskingEngine;
      reg!(s, "data", "Tokenizer", Tokenizer::new().with_metrics(m.clone()));
      reg!(s, "data", "DLP Scanner", DlpScanner::new().with_metrics(m.clone()));
      reg!(s, "data", "Access Controller", AccessController::new().with_metrics(m.clone()));
      reg!(s, "data", "Backup Manager", BackupManager::new().with_metrics(m.clone()));
      reg!(s, "data", "Classification", ClassificationEngine::new().with_metrics(m.clone()));
      reg!(s, "data", "Encryption Engine", EncryptionEngine::new().with_metrics(m.clone()));
      reg!(s, "data", "Integrity Checker", IntegrityChecker::new().with_metrics(m.clone()));
      reg!(s, "data", "Key Manager", KeyManager::new().with_metrics(m.clone()));
      reg!(s, "data", "Masking Engine", MaskingEngine::new().with_metrics(m.clone()));
      dom!(d, "data", "Data Protection", 9); }

    // ── 9. Threat Intel (7 modules) ──
    { use sentinel_threat_intel::stix_parser::StixParser;
      use sentinel_threat_intel::enrichment_engine::EnrichmentEngine;
      use sentinel_threat_intel::feed_manager::FeedManager;
      use sentinel_threat_intel::ioc_store::IocStore;
      use sentinel_threat_intel::reputation_engine::ReputationEngine;
      use sentinel_threat_intel::sharing_hub::SharingHub;
      use sentinel_threat_intel::threat_correlator::ThreatCorrelator;
      reg!(s, "threat_intel", "STIX Parser", StixParser::new().with_metrics(m.clone()));
      reg!(s, "threat_intel", "Enrichment Engine", EnrichmentEngine::new().with_metrics(m.clone()));
      reg!(s, "threat_intel", "Feed Manager", FeedManager::new().with_metrics(m.clone()));
      reg!(s, "threat_intel", "IOC Store", IocStore::new().with_metrics(m.clone()));
      reg!(s, "threat_intel", "Reputation Engine", ReputationEngine::new().with_metrics(m.clone()));
      reg!(s, "threat_intel", "Sharing Hub", SharingHub::new().with_metrics(m.clone()));
      reg!(s, "threat_intel", "Threat Correlator", ThreatCorrelator::new(2).with_metrics(m.clone()));
      dom!(d, "threat_intel", "Threat Intelligence", 7); }

    // ── 10. Forensics (7 modules) ──
    { use sentinel_forensics::evidence_collector::EvidenceCollector;
      use sentinel_forensics::timeline_builder::TimelineBuilder;
      use sentinel_forensics::artifact_extractor::ArtifactExtractor;
      use sentinel_forensics::report_writer::ReportWriter;
      use sentinel_forensics::chain_of_custody::ChainOfCustody;
      use sentinel_forensics::disk_imager::DiskImager;
      use sentinel_forensics::memory_analyzer::MemoryAnalyzer;
      reg!(s, "forensics", "Evidence Collector", EvidenceCollector::new().with_metrics(m.clone()));
      reg!(s, "forensics", "Timeline Builder", TimelineBuilder::new().with_metrics(m.clone()));
      reg!(s, "forensics", "Artifact Extractor", ArtifactExtractor::new().with_metrics(m.clone()));
      reg!(s, "forensics", "Report Writer", ReportWriter::new().with_metrics(m.clone()));
      reg!(s, "forensics", "Chain of Custody", ChainOfCustody::new().with_metrics(m.clone()));
      reg!(s, "forensics", "Disk Imager", DiskImager::new().with_metrics(m.clone()));
      reg!(s, "forensics", "Memory Analyzer", MemoryAnalyzer::new().with_metrics(m.clone()));
      dom!(d, "forensics", "Digital Forensics", 7); }

    // ── 11. Vuln (6 modules) ──
    { use sentinel_vuln::cve_database::CveDatabase;
      use sentinel_vuln::exploit_detector::ExploitDetector;
      use sentinel_vuln::patch_manager::PatchManager;
      use sentinel_vuln::remediation_engine::RemediationEngine;
      use sentinel_vuln::risk_scorer::RiskScorer;
      use sentinel_vuln::scanner::VulnScanner;
      reg!(s, "vuln", "CVE Database", CveDatabase::new().with_metrics(m.clone()));
      reg!(s, "vuln", "Exploit Detector", ExploitDetector::new().with_metrics(m.clone()));
      reg!(s, "vuln", "Patch Manager", PatchManager::new().with_metrics(m.clone()));
      reg!(s, "vuln", "Remediation Engine", RemediationEngine::new().with_metrics(m.clone()));
      reg!(s, "vuln", "Risk Scorer", RiskScorer::new().with_metrics(m.clone()));
      reg!(s, "vuln", "Vuln Scanner", VulnScanner::new().with_metrics(m.clone()));
      dom!(d, "vuln", "Vulnerability Mgmt", 6); }

    // ── 12. Web (5 modules) ──
    { use sentinel_web::waf_engine::WafEngine;
      use sentinel_web::bot_detector::BotDetector;
      use sentinel_web::content_scanner::ContentScanner;
      use sentinel_web::session_protector::SessionProtector;
      use sentinel_web::ssl_inspector::SslInspector;
      reg!(s, "web", "WAF Engine", WafEngine::new().with_metrics(m.clone()));
      reg!(s, "web", "Bot Detector", BotDetector::new(100).with_metrics(m.clone()));
      reg!(s, "web", "Content Scanner", ContentScanner::new().with_metrics(m.clone()));
      reg!(s, "web", "Session Protector", SessionProtector::new().with_metrics(m.clone()));
      reg!(s, "web", "SSL Inspector", SslInspector::new().with_metrics(m.clone()));
      dom!(d, "web", "Web App Security", 5); }

    // ── 13. Container (5 modules) ──
    { use sentinel_container::image_scanner::ImageScanner;
      use sentinel_container::runtime_monitor::RuntimeMonitor;
      use sentinel_container::secret_manager::SecretManager;
      use sentinel_container::policy_enforcer::PolicyEnforcer;
      use sentinel_container::registry_guard::RegistryGuard;
      reg!(s, "container", "Image Scanner", ImageScanner::new().with_metrics(m.clone()));
      reg!(s, "container", "Runtime Monitor", RuntimeMonitor::new(0.9).with_metrics(m.clone()));
      reg!(s, "container", "Secret Manager", SecretManager::new().with_metrics(m.clone()));
      reg!(s, "container", "Policy Enforcer", PolicyEnforcer::new().with_metrics(m.clone()));
      reg!(s, "container", "Registry Guard", RegistryGuard::new().with_metrics(m.clone()));
      dom!(d, "container", "Container Security", 5); }

    // ── 14. Supply Chain (5 modules, no with_metrics) ──
    { use sentinel_supply_chain::sbom_manager::SbomManager;
      use sentinel_supply_chain::license_checker::LicenseChecker;
      use sentinel_supply_chain::artifact_verifier::ArtifactVerifier;
      use sentinel_supply_chain::build_integrity::BuildIntegrity;
      use sentinel_supply_chain::dependency_scanner::DependencyScanner;
      reg!(s, "supply_chain", "SBOM Manager", SbomManager::new());
      reg!(s, "supply_chain", "License Checker", LicenseChecker::new());
      reg!(s, "supply_chain", "Artifact Verifier", ArtifactVerifier::new());
      reg!(s, "supply_chain", "Build Integrity", BuildIntegrity::new());
      reg!(s, "supply_chain", "Dependency Scanner", DependencyScanner::new());
      dom!(d, "supply_chain", "Supply Chain", 5); }

    // ── 15. Compliance (5 modules) ──
    { use sentinel_compliance::policy_engine::PolicyEngine;
      use sentinel_compliance::audit_logger::AuditLogger;
      use sentinel_compliance::report_generator::ReportGenerator;
      use sentinel_compliance::control_mapper::ControlMapper;
      use sentinel_compliance::gap_analyzer::GapAnalyzer;
      reg!(s, "compliance", "Policy Engine", PolicyEngine::new().with_metrics(m.clone()));
      reg!(s, "compliance", "Audit Logger", AuditLogger::new().with_metrics(m.clone()));
      reg!(s, "compliance", "Report Generator", ReportGenerator::new().with_metrics(m.clone()));
      reg!(s, "compliance", "Control Mapper", ControlMapper::new().with_metrics(m.clone()));
      reg!(s, "compliance", "Gap Analyzer", GapAnalyzer::new().with_metrics(m.clone()));
      dom!(d, "compliance", "Compliance", 5); }

    // ── 16. Privacy (6 modules) ──
    { use sentinel_privacy::consent_manager::ConsentManager;
      use sentinel_privacy::retention_enforcer::RetentionEnforcer;
      use sentinel_privacy::dsar_handler::DsarHandler;
      use sentinel_privacy::pii_scanner::PiiScanner;
      use sentinel_privacy::anonymizer::Anonymizer;
      use sentinel_privacy::tracker_blocker::TrackerBlocker;
      reg!(s, "privacy", "Consent Manager", ConsentManager::new());
      reg!(s, "privacy", "Retention Enforcer", RetentionEnforcer::new());
      reg!(s, "privacy", "DSAR Handler", DsarHandler::new());
      reg!(s, "privacy", "PII Scanner", PiiScanner::new());
      reg!(s, "privacy", "Anonymizer", Anonymizer::new());
      reg!(s, "privacy", "Tracker Blocker", TrackerBlocker::new().with_metrics(m.clone()));
      dom!(d, "privacy", "Privacy", 6); }

    // ── 17. AI Agent Security (55 modules — most comprehensive AI security layer in existence) ──
    { // ── Imports: Core AI monitoring ─────────────────────────────────────
      use sentinel_ai::shadow_ai_detector::ShadowAiDetector;
      use sentinel_ai::api_key_monitor::ApiKeyMonitor;
      use sentinel_ai::prompt_guard::PromptGuard;
      use sentinel_ai::model_scanner::ModelScanner;
      use sentinel_ai::output_filter::OutputFilter;
      use sentinel_ai::local_sandbox::LocalSandbox;
      use sentinel_ai::data_poisoning_detector::DataPoisoningDetector;
      // ── Imports: Pre-inference defense ──────────────────────────────────
      use sentinel_ai::semantic_firewall::SemanticFirewall;
      use sentinel_ai::indirect_injection_scanner::IndirectInjectionScanner;
      use sentinel_ai::multi_turn_tracker::MultiTurnTracker;
      use sentinel_ai::token_smuggling_detector::TokenSmugglingDetector;
      use sentinel_ai::context_window_stuffing_guard::ContextWindowStuffingGuard;
      use sentinel_ai::instruction_hierarchy_enforcer::InstructionHierarchyEnforcer;
      use sentinel_ai::capability_probe_detector::CapabilityProbeDetector;
      // ── Imports: Agent runtime security ─────────────────────────────────
      use sentinel_ai::tool_call_validator::ToolCallValidator;
      use sentinel_ai::tool_integrity_verifier::ToolIntegrityVerifier;
      use sentinel_ai::agent_action_logger::AgentActionLogger;
      use sentinel_ai::agent_permission_boundary::AgentPermissionBoundary;
      use sentinel_ai::agent_network_fence::AgentNetworkFence;
      use sentinel_ai::agent_behavior_baseline::AgentBehaviorBaseline;
      use sentinel_ai::agent_session_recorder::AgentSessionRecorder;
      use sentinel_ai::agent_cost_monitor::AgentCostMonitor;
      use sentinel_ai::agent_identity_attestation::AgentIdentityAttestation;
      use sentinel_ai::clipboard_exfil_detector::ClipboardExfilDetector;
      use sentinel_ai::multi_agent_conflict::MultiAgentConflictDetector;
      use sentinel_ai::delegation_chain_auditor::DelegationChainAuditor;
      use sentinel_ai::cross_plugin_data_fence::CrossPluginDataFence;
      use sentinel_ai::autonomous_agent_containment::AutonomousAgentContainment;
      // ── Imports: Post-inference & output ────────────────────────────────
      use sentinel_ai::output_watermarker::OutputWatermarker;
      use sentinel_ai::hallucination_detector::HallucinationDetector;
      use sentinel_ai::conversation_state_integrity::ConversationStateIntegrity;
      // ── Imports: Continuous monitoring ──────────────────────────────────
      use sentinel_ai::rag_poisoning_detector::RagPoisoningDetector;
      use sentinel_ai::mcp_protocol_security::McpProtocolSecurity;
      use sentinel_ai::reasoning_trace_auditor::ReasoningTraceAuditor;
      use sentinel_ai::memory_poisoning_guard::MemoryPoisoningGuard;
      use sentinel_ai::sleeper_agent_detector::SleeperAgentDetector;
      use sentinel_ai::goal_drift_monitor::GoalDriftMonitor;
      use sentinel_ai::agentic_loop_detector::AgenticLoopDetector;
      use sentinel_ai::human_in_the_loop_enforcer::HumanInTheLoopEnforcer;
      use sentinel_ai::model_extraction_guard::ModelExtractionGuard;
      use sentinel_ai::adversarial_input_detector::AdversarialInputDetector;
      use sentinel_ai::ai_supply_chain_attestation::AiSupplyChainAttestation;
      use sentinel_ai::security_pipeline::SecurityPipeline;
      // ── Imports: NEW Tier 1 — Critical AI defense ──────────────────────
      use sentinel_ai::system_prompt_guardian::SystemPromptGuardian;
      use sentinel_ai::multimodal_injection_scanner::MultimodalInjectionScanner;
      use sentinel_ai::jailbreak_classifier::JailbreakClassifier;
      use sentinel_ai::training_data_extraction_guard::TrainingDataExtractionGuard;
      use sentinel_ai::embedding_space_monitor::EmbeddingSpaceMonitor;
      // ── Imports: NEW Tier 2 — Important AI defense ─────────────────────
      use sentinel_ai::synthetic_content_detector::SyntheticContentDetector;
      use sentinel_ai::fine_tuning_attack_detector::FineTuningAttackDetector;
      use sentinel_ai::reward_hacking_detector::RewardHackingDetector;
      use sentinel_ai::model_drift_sentinel::ModelDriftSentinel;
      // ── Imports: NEW — Agent plan review & response integrity ────────
      use sentinel_ai::plan_review_engine::PlanReviewEngine;
      use sentinel_ai::response_integrity_analyzer::ResponseIntegrityAnalyzer;

      // ── Registration: Core AI monitoring ───────────────────────────────
      reg!(s, "ai", "Shadow AI Detector", ShadowAiDetector::new().with_metrics(m.clone()));
      reg!(s, "ai", "API Key Monitor", ApiKeyMonitor::new().with_metrics(m.clone()));
      reg!(s, "ai", "Prompt Guard", PromptGuard::new());
      reg!(s, "ai", "Model Scanner", ModelScanner::new());
      reg!(s, "ai", "Output Filter", OutputFilter::new());
      reg!(s, "ai", "Local Sandbox", LocalSandbox::new().with_metrics(m.clone()));
      reg!(s, "ai", "Data Poisoning", DataPoisoningDetector::new(0.8));
      // ── Registration: Pre-inference defense ────────────────────────────
      reg!(s, "ai", "Semantic Firewall", SemanticFirewall::new());
      reg!(s, "ai", "Indirect Injection Scanner", IndirectInjectionScanner::new());
      reg!(s, "ai", "Multi-Turn Tracker", MultiTurnTracker::new());
      reg!(s, "ai", "Token Smuggling Detect", TokenSmugglingDetector::new().with_metrics(m.clone()));
      reg!(s, "ai", "Context Stuffing Guard", ContextWindowStuffingGuard::new().with_metrics(m.clone()));
      reg!(s, "ai", "Instruction Hierarchy", InstructionHierarchyEnforcer::new().with_metrics(m.clone()));
      reg!(s, "ai", "Capability Probe Detect", CapabilityProbeDetector::new().with_metrics(m.clone()));
      // ── Registration: Agent runtime security ───────────────────────────
      reg!(s, "ai", "Tool Call Validator", ToolCallValidator::new().with_metrics(m.clone()));
      reg!(s, "ai", "Tool Integrity Verifier", ToolIntegrityVerifier::new().with_metrics(m.clone()));
      reg!(s, "ai", "Agent Action Logger", AgentActionLogger::new().with_metrics(m.clone()));
      reg!(s, "ai", "Agent Permissions", AgentPermissionBoundary::new().with_metrics(m.clone()));
      reg!(s, "ai", "Agent Network Fence", AgentNetworkFence::new().with_metrics(m.clone()));
      reg!(s, "ai", "Behavior Baseline", AgentBehaviorBaseline::new().with_metrics(m.clone()));
      reg!(s, "ai", "Session Recorder", AgentSessionRecorder::new().with_metrics(m.clone()));
      reg!(s, "ai", "Agent Cost Monitor", AgentCostMonitor::new().with_metrics(m.clone()));
      reg!(s, "ai", "Agent Identity Attest", AgentIdentityAttestation::new().with_metrics(m.clone()));
      reg!(s, "ai", "Clipboard Exfil Detect", ClipboardExfilDetector::new().with_metrics(m.clone()));
      reg!(s, "ai", "Multi-Agent Conflict", MultiAgentConflictDetector::new().with_metrics(m.clone()));
      reg!(s, "ai", "Delegation Chain Audit", DelegationChainAuditor::new().with_metrics(m.clone()));
      reg!(s, "ai", "Cross-Plugin Fence", CrossPluginDataFence::new().with_metrics(m.clone()));
      reg!(s, "ai", "Agent Containment", AutonomousAgentContainment::new().with_metrics(m.clone()));
      // ── Registration: Post-inference & output ──────────────────────────
      reg!(s, "ai", "Output Watermarker", OutputWatermarker::new());
      reg!(s, "ai", "Hallucination Detector", HallucinationDetector::new());
      reg!(s, "ai", "Conversation Integrity", ConversationStateIntegrity::new());
      // ── Registration: Continuous monitoring ────────────────────────────
      reg!(s, "ai", "RAG Poisoning", RagPoisoningDetector::new().with_metrics(m.clone()));
      reg!(s, "ai", "MCP Protocol Security", McpProtocolSecurity::new().with_metrics(m.clone()));
      reg!(s, "ai", "Reasoning Trace Auditor", ReasoningTraceAuditor::new().with_metrics(m.clone()));
      reg!(s, "ai", "Memory Poisoning Guard", MemoryPoisoningGuard::new().with_metrics(m.clone()));
      reg!(s, "ai", "Sleeper Agent Detect", SleeperAgentDetector::new().with_metrics(m.clone()));
      reg!(s, "ai", "Goal Drift Monitor", GoalDriftMonitor::new().with_metrics(m.clone()));
      reg!(s, "ai", "Agentic Loop Detect", AgenticLoopDetector::new().with_metrics(m.clone()));
      reg!(s, "ai", "Human-in-the-Loop", HumanInTheLoopEnforcer::new().with_metrics(m.clone()));
      reg!(s, "ai", "Model Extraction Guard", ModelExtractionGuard::new().with_metrics(m.clone()));
      reg!(s, "ai", "Adversarial Input Detect", AdversarialInputDetector::new().with_metrics(m.clone()));
      reg!(s, "ai", "AI Supply Chain Attest", AiSupplyChainAttestation::new().with_metrics(m.clone()));
      reg!(s, "ai", "Security Pipeline", SecurityPipeline::new());
      // ── Registration: NEW Tier 1 — Critical AI defense ─────────────────
      reg!(s, "ai", "System Prompt Guardian", SystemPromptGuardian::new());
      reg!(s, "ai", "Multimodal Injection Scan", MultimodalInjectionScanner::new());
      reg!(s, "ai", "Jailbreak Classifier", JailbreakClassifier::new());
      reg!(s, "ai", "Training Data Guard", TrainingDataExtractionGuard::new());
      reg!(s, "ai", "Embedding Space Monitor", EmbeddingSpaceMonitor::new());
      // ── Registration: NEW Tier 2 — Important AI defense ────────────────
      reg!(s, "ai", "Synthetic Content Detect", SyntheticContentDetector::new());
      reg!(s, "ai", "Fine-Tuning Attack Detect", FineTuningAttackDetector::new());
      reg!(s, "ai", "Reward Hacking Detect", RewardHackingDetector::new());
      reg!(s, "ai", "Model Drift Sentinel", ModelDriftSentinel::new());
      use sentinel_ai::local_ai_discovery::LocalAiDiscovery;
      reg!(s, "ai", "Local AI Discovery", LocalAiDiscovery::new());
      // ── Registration: Agent plan review & response integrity ──────────
      reg!(s, "ai", "Plan Review Engine", PlanReviewEngine::new());
      reg!(s, "ai", "Response Integrity", ResponseIntegrityAnalyzer::new());
      dom!(d, "ai", "AI Agent Security", 55); }

    // ── 18. Deception (6 modules) ──
    { use sentinel_deception::dns_canary::DnsCanary;
      use sentinel_deception::honey_file::HoneyFile;
      use sentinel_deception::attacker_profiler::AttackerProfiler;
      use sentinel_deception::decoy_network::DecoyNetwork;
      use sentinel_deception::honey_token::HoneyTokenManager;
      use sentinel_deception::honeypot_manager::HoneypotManager;
      reg!(s, "deception", "DNS Canary", DnsCanary::new().with_metrics(m.clone()));
      reg!(s, "deception", "Honey File", HoneyFile::new().with_metrics(m.clone()));
      reg!(s, "deception", "Attacker Profiler", AttackerProfiler::new());
      reg!(s, "deception", "Decoy Network", DecoyNetwork::new());
      reg!(s, "deception", "Honey Token", HoneyTokenManager::new());
      reg!(s, "deception", "Honeypot Manager", HoneypotManager::new());
      dom!(d, "deception", "Deception Tech", 6); }

    // ── 19. Browser (5 modules) ──
    { use sentinel_browser::download_scanner::DownloadScanner;
      use sentinel_browser::cookie_guard::CookieGuard;
      use sentinel_browser::extension_scanner::ExtensionScanner;
      use sentinel_browser::script_analyzer::ScriptAnalyzer;
      use sentinel_browser::url_filter::UrlFilter;
      reg!(s, "browser", "Download Scanner", DownloadScanner::new().with_metrics(m.clone()));
      reg!(s, "browser", "Cookie Guard", CookieGuard::new());
      reg!(s, "browser", "Extension Scanner", ExtensionScanner::new());
      reg!(s, "browser", "Script Analyzer", ScriptAnalyzer::new());
      reg!(s, "browser", "URL Filter", UrlFilter::new());
      dom!(d, "browser", "Browser Security", 5); }

    // ── 20. API Security (5 modules) ──
    { use sentinel_api::graphql_blocker::GraphqlBlocker;
      use sentinel_api::auth_enforcer::AuthEnforcer;
      use sentinel_api::payload_inspector::PayloadInspector;
      use sentinel_api::rate_limiter::RateLimiter as ApiRateLimiter;
      use sentinel_api::schema_validator::SchemaValidator;
      reg!(s, "api", "GraphQL Blocker", GraphqlBlocker::new(10).with_metrics(m.clone()));
      reg!(s, "api", "Auth Enforcer", AuthEnforcer::new());
      reg!(s, "api", "Payload Inspector", PayloadInspector::new());
      reg!(s, "api", "Rate Limiter", ApiRateLimiter::new(1000));
      reg!(s, "api", "Schema Validator", SchemaValidator::new());
      dom!(d, "api", "API Security", 5); }

    // ── 21. VPN (4 modules, no with_metrics) ──
    { use sentinel_vpn::tunnel_monitor::TunnelMonitor;
      use sentinel_vpn::split_tunnel::SplitTunnel;
      use sentinel_vpn::leak_detector::LeakDetector;
      use sentinel_vpn::access_controller::AccessController as VpnAccessController;
      reg!(s, "vpn", "Tunnel Monitor", TunnelMonitor::new());
      reg!(s, "vpn", "Split Tunnel", SplitTunnel::new());
      reg!(s, "vpn", "Leak Detector", LeakDetector::new());
      reg!(s, "vpn", "Access Controller", VpnAccessController::new());
      dom!(d, "vpn", "VPN Security", 4); }

    // ── 22. Hardware (4 modules, no with_metrics) ──
    { use sentinel_hardware::device_guard::DeviceGuard;
      use sentinel_hardware::tpm_manager::TpmManager;
      use sentinel_hardware::secure_boot::SecureBoot;
      use sentinel_hardware::firmware_scanner::FirmwareScanner;
      reg!(s, "hardware", "Device Guard", DeviceGuard::new());
      reg!(s, "hardware", "TPM Manager", TpmManager::new());
      reg!(s, "hardware", "Secure Boot", SecureBoot::new());
      reg!(s, "hardware", "Firmware Scanner", FirmwareScanner::new());
      dom!(d, "hardware", "Hardware Security", 4); }

    // ── 23. Exfiltration (4 modules, no with_metrics) ──
    { use sentinel_exfiltration::channel_detector::ChannelDetector;
      use sentinel_exfiltration::volume_monitor::VolumeMonitor;
      use sentinel_exfiltration::clipboard_guard::ClipboardGuard;
      use sentinel_exfiltration::watermarker::Watermarker;
      reg!(s, "exfiltration", "Channel Detector", ChannelDetector::new(0.7));
      reg!(s, "exfiltration", "Volume Monitor", VolumeMonitor::new(3.0));
      reg!(s, "exfiltration", "Clipboard Guard", ClipboardGuard::new());
      reg!(s, "exfiltration", "Watermarker", Watermarker::new());
      dom!(d, "exfiltration", "Data Exfiltration", 4); }

    // ── 24. Management (7 modules) ──
    { use sentinel_mgmt::health_monitor::HealthMonitor;
      use sentinel_mgmt::alert_feed::AlertFeed;
      use sentinel_mgmt::api_gateway::ApiGateway;
      use sentinel_mgmt::config_manager::ConfigManager;
      use sentinel_mgmt::dashboard::Dashboard as MgmtDashboard;
      use sentinel_mgmt::device_inventory::DeviceInventory;
      use sentinel_mgmt::update_manager::UpdateManager;
      reg!(s, "mgmt", "Health Monitor", HealthMonitor::new().with_metrics(m.clone()));
      reg!(s, "mgmt", "Alert Feed", AlertFeed::new().with_metrics(m.clone()));
      reg!(s, "mgmt", "API Gateway", ApiGateway::new().with_metrics(m.clone()));
      reg!(s, "mgmt", "Config Manager", ConfigManager::new().with_metrics(m.clone()));
      reg!(s, "mgmt", "Dashboard", MgmtDashboard::new().with_metrics(m.clone()));
      reg!(s, "mgmt", "Device Inventory", DeviceInventory::new().with_metrics(m.clone()));
      reg!(s, "mgmt", "Update Manager", UpdateManager::new().with_metrics(m.clone()));
      dom!(d, "mgmt", "Management", 7); }

    // ── 25. Self-Protection (4 modules) ──
    { use sentinel_selfprotect::binary_integrity::BinaryIntegrity;
      use sentinel_selfprotect::anti_tampering::AntiTampering;
      use sentinel_selfprotect::config_protection::ConfigProtection;
      use sentinel_selfprotect::secure_updates::SecureUpdates;
      reg!(s, "selfprotect", "Binary Integrity", BinaryIntegrity::new().with_metrics(m.clone()));
      reg!(s, "selfprotect", "Anti-Tampering", AntiTampering::new().with_metrics(m.clone()));
      reg!(s, "selfprotect", "Config Protection", ConfigProtection::new().with_metrics(m.clone()));
      reg!(s, "selfprotect", "Secure Updates", SecureUpdates::new().with_metrics(m.clone()));
      dom!(d, "selfprotect", "Self-Protection", 4); }

    // ── 26. Phishing (4 modules) ──
    { use sentinel_phishing::lookalike_domain::LookalikeDomainMonitor;
      use sentinel_phishing::link_scanner::LinkScanner;
      use sentinel_phishing::qr_scanner::QrScanner;
      use sentinel_phishing::vishing_detector::VishingDetector;
      reg!(s, "phishing", "Lookalike Domain", LookalikeDomainMonitor::new().with_metrics(m.clone()));
      reg!(s, "phishing", "Link Scanner", LinkScanner::new().with_metrics(m.clone()));
      reg!(s, "phishing", "QR Scanner", QrScanner::new().with_metrics(m.clone()));
      reg!(s, "phishing", "Vishing Detector", VishingDetector::new().with_metrics(m.clone()));
      dom!(d, "phishing", "Anti-Phishing", 4); }

    // ── 27. Crypto (4 modules) ──
    { use sentinel_crypto::tls_auditor::TlsAuditor;
      use sentinel_crypto::ca_monitor::CaMonitor;
      use sentinel_crypto::key_rotation::KeyRotation;
      use sentinel_crypto::quantum_readiness::QuantumReadiness;
      reg!(s, "crypto", "TLS Auditor", TlsAuditor::new().with_metrics(m.clone()));
      reg!(s, "crypto", "CA Monitor", CaMonitor::new().with_metrics(m.clone()));
      reg!(s, "crypto", "Key Rotation", KeyRotation::new().with_metrics(m.clone()));
      reg!(s, "crypto", "Quantum Readiness", QuantumReadiness::new().with_metrics(m.clone()));
      dom!(d, "crypto", "Cryptography", 4); }

    // ── 28. Resilience (4 modules) ──
    { use sentinel_resilience::auto_quarantine::AutoQuarantine;
      use sentinel_resilience::kill_switch::KillSwitch;
      use sentinel_resilience::dr_tester::DrTester;
      use sentinel_resilience::rollback_engine::RollbackEngine;
      reg!(s, "resilience", "Auto-Quarantine", AutoQuarantine::new().with_metrics(m.clone()));
      reg!(s, "resilience", "Kill Switch", KillSwitch::new().with_metrics(m.clone()));
      reg!(s, "resilience", "DR Tester", DrTester::new().with_metrics(m.clone()));
      reg!(s, "resilience", "Rollback Engine", RollbackEngine::new().with_metrics(m.clone()));
      dom!(d, "resilience", "Resilience", 4); }

    // ── 29. Mobile (5 modules) ──
    { use sentinel_mobile::app_permission_auditor::AppPermissionAuditor;
      use sentinel_mobile::network_traffic_monitor::NetworkTrafficMonitor;
      use sentinel_mobile::mdm_lite::MdmLite;
      use sentinel_mobile::rogue_app_store::RogueAppStore;
      use sentinel_mobile::sim_swap_detector::SimSwapDetector;
      reg!(s, "mobile", "App Permissions", AppPermissionAuditor::new().with_metrics(m.clone()));
      reg!(s, "mobile", "Traffic Monitor", NetworkTrafficMonitor::new().with_metrics(m.clone()));
      reg!(s, "mobile", "MDM Lite", MdmLite::new().with_metrics(m.clone()));
      reg!(s, "mobile", "Rogue App Store", RogueAppStore::new().with_metrics(m.clone()));
      reg!(s, "mobile", "SIM Swap Detect", SimSwapDetector::new().with_metrics(m.clone()));
      dom!(d, "mobile", "Mobile Security", 5); }

    // ── 30. Dark Web (4 modules) ──
    { use sentinel_darkweb::domain_reputation::DomainReputationMonitor;
      use sentinel_darkweb::exposed_service_detector::ExposedServiceDetector;
      use sentinel_darkweb::breach_credential_monitor::BreachCredentialMonitor;
      use sentinel_darkweb::ct_watcher::CtWatcher;
      reg!(s, "darkweb", "Domain Reputation", DomainReputationMonitor::new().with_metrics(m.clone()));
      reg!(s, "darkweb", "Exposed Services", ExposedServiceDetector::new().with_metrics(m.clone()));
      reg!(s, "darkweb", "Breach Credentials", BreachCredentialMonitor::new().with_metrics(m.clone()));
      reg!(s, "darkweb", "CT Watcher", CtWatcher::new().with_metrics(m.clone()));
      dom!(d, "darkweb", "Dark Web Intel", 4); }

    // ── 31. OT/ICS (4 modules) ──
    { use sentinel_ot::scada_monitor::ScadaMonitor;
      use sentinel_ot::serial_monitor::SerialMonitor;
      use sentinel_ot::plc_integrity::PlcIntegrity;
      use sentinel_ot::safety_validator::SafetyValidator;
      reg!(s, "ot", "SCADA Monitor", ScadaMonitor::new().with_metrics(m.clone()));
      reg!(s, "ot", "Serial Monitor", SerialMonitor::new().with_metrics(m.clone()));
      reg!(s, "ot", "PLC Integrity", PlcIntegrity::new().with_metrics(m.clone()));
      reg!(s, "ot", "Safety Validator", SafetyValidator::new().with_metrics(m.clone()));
      dom!(d, "ot", "OT/ICS Security", 4); }

    // ── 32. Micro-Segmentation (3 modules) ──
    { use sentinel_microseg::zero_trust_engine::ZeroTrustEngine;
      use sentinel_microseg::lateral_movement_detector::LateralMovementDetector;
      use sentinel_microseg::micro_perimeter::MicroPerimeter;
      reg!(s, "microseg", "Zero Trust", ZeroTrustEngine::new().with_metrics(m.clone()));
      reg!(s, "microseg", "Lateral Movement", LateralMovementDetector::new().with_metrics(m.clone()));
      reg!(s, "microseg", "Micro Perimeter", MicroPerimeter::new().with_metrics(m.clone()));
      dom!(d, "microseg", "Micro-Segmentation", 3); }

    // ── 33. Backup (6 modules) ──
    { use sentinel_backup::immutable_backup_validator::ImmutableBackupValidator;
      use sentinel_backup::config_drift_detector::ConfigDriftDetector;
      use sentinel_backup::encryption_auditor::EncryptionAuditor;
      use sentinel_backup::golden_image_comparator::GoldenImageComparator;
      use sentinel_backup::integrity_verifier::IntegrityVerifier;
      use sentinel_backup::retention_manager::RetentionManager;
      reg!(s, "backup", "Immutable Backup", ImmutableBackupValidator::new().with_metrics(m.clone()));
      reg!(s, "backup", "Config Drift", ConfigDriftDetector::new().with_metrics(m.clone()));
      reg!(s, "backup", "Encryption Auditor", EncryptionAuditor::new().with_metrics(m.clone()));
      reg!(s, "backup", "Golden Image", GoldenImageComparator::new().with_metrics(m.clone()));
      reg!(s, "backup", "Integrity Verifier", IntegrityVerifier::new().with_metrics(m.clone()));
      reg!(s, "backup", "Retention Manager", RetentionManager::new().with_metrics(m.clone()));
      dom!(d, "backup", "Backup Security", 6); }

    // ── 34. Cloud (8 modules) ──
    { use sentinel_cloud::storage_exposure::StorageExposure;
      use sentinel_cloud::oauth_auditor::OauthAuditor;
      use sentinel_cloud::credential_leak_detector::CredentialLeakDetector;
      use sentinel_cloud::iam_auditor::IamAuditor;
      use sentinel_cloud::network_exposure::NetworkExposure;
      use sentinel_cloud::serverless_monitor::ServerlessMonitor;
      use sentinel_cloud::shadow_it_detector::ShadowItDetector;
      use sentinel_cloud::storage_scanner::StorageScanner;
      reg!(s, "cloud", "Storage Exposure", StorageExposure::new().with_metrics(m.clone()));
      reg!(s, "cloud", "OAuth Auditor", OauthAuditor::new().with_metrics(m.clone()));
      reg!(s, "cloud", "Credential Leak", CredentialLeakDetector::new().with_metrics(m.clone()));
      reg!(s, "cloud", "IAM Auditor", IamAuditor::new(true));
      reg!(s, "cloud", "Network Exposure", NetworkExposure::new().with_metrics(m.clone()));
      reg!(s, "cloud", "Serverless Monitor", ServerlessMonitor::new().with_metrics(m.clone()));
      reg!(s, "cloud", "Shadow IT", ShadowItDetector::new().with_metrics(m.clone()));
      reg!(s, "cloud", "Storage Scanner", StorageScanner::new().with_metrics(m.clone()));
      dom!(d, "cloud", "Cloud Security", 8); }

    // ── 35. Time (3 modules) ──
    { use sentinel_time::ntp_integrity::NtpIntegrity;
      use sentinel_time::timestamp_validator::TimestampValidator;
      use sentinel_time::ntp_monitor::NtpMonitor;
      reg!(s, "time", "NTP Integrity", NtpIntegrity::new().with_metrics(m.clone()));
      reg!(s, "time", "Timestamp Validator", TimestampValidator::new(1000).with_metrics(m.clone()));
      reg!(s, "time", "NTP Monitor", NtpMonitor::new().with_metrics(m.clone()));
      dom!(d, "time", "Time Security", 3); }

    // ── 36. Social Engineering (6 modules) ──
    { use sentinel_soceng::osint_monitor::OsintMonitor;
      use sentinel_soceng::deepfake_detector::DeepfakeDetector;
      use sentinel_soceng::awareness_tracker::AwarenessTracker;
      use sentinel_soceng::impersonation_detector::ImpersonationDetector;
      use sentinel_soceng::phishing_simulator::PhishingSimulator;
      use sentinel_soceng::pretexting_detector::PretextingDetector;
      reg!(s, "soceng", "OSINT Monitor", OsintMonitor::new().with_metrics(m.clone()));
      reg!(s, "soceng", "Deepfake Detector", DeepfakeDetector::new().with_metrics(m.clone()));
      reg!(s, "soceng", "Awareness Tracker", AwarenessTracker::new().with_metrics(m.clone()));
      reg!(s, "soceng", "Impersonation", ImpersonationDetector::new().with_metrics(m.clone()));
      reg!(s, "soceng", "Phishing Simulator", PhishingSimulator::new().with_metrics(m.clone()));
      reg!(s, "soceng", "Pretexting Detect", PretextingDetector::new().with_metrics(m.clone()));
      dom!(d, "soceng", "Social Engineering", 6); }

    // ── 37. Regulatory (6 modules) ──
    { use sentinel_regulatory::gdpr_mapper::GdprMapper;
      use sentinel_regulatory::legal_hold::LegalHold;
      use sentinel_regulatory::cross_border_monitor::CrossBorderMonitor;
      use sentinel_regulatory::gdpr_monitor::GdprMonitor;
      use sentinel_regulatory::hipaa_monitor::HipaaMonitor;
      use sentinel_regulatory::pci_scanner::PciScanner;
      reg!(s, "regulatory", "GDPR Mapper", GdprMapper::new().with_metrics(m.clone()));
      reg!(s, "regulatory", "Legal Hold", LegalHold::new().with_metrics(m.clone()));
      reg!(s, "regulatory", "Cross-Border", CrossBorderMonitor::new().with_metrics(m.clone()));
      reg!(s, "regulatory", "GDPR Monitor", GdprMonitor::new().with_metrics(m.clone()));
      reg!(s, "regulatory", "HIPAA Monitor", HipaaMonitor::new().with_metrics(m.clone()));
      reg!(s, "regulatory", "PCI Scanner", PciScanner::new().with_metrics(m.clone()));
      dom!(d, "regulatory", "Regulatory", 6); }

    // ── 38. Operations (6 modules) ──
    { use sentinel_ops::service_availability::ServiceAvailability;
      use sentinel_ops::performance_baseline::PerformanceBaseline;
      use sentinel_ops::power_monitor::PowerMonitor;
      use sentinel_ops::runbook_engine::RunbookEngine;
      use sentinel_ops::sla_tracker::SlaTracker;
      use sentinel_ops::ticket_integrator::TicketIntegrator;
      reg!(s, "ops", "Service Availability", ServiceAvailability::new().with_metrics(m.clone()));
      reg!(s, "ops", "Performance Baseline", PerformanceBaseline::new().with_metrics(m.clone()));
      reg!(s, "ops", "Power Monitor", PowerMonitor::new().with_metrics(m.clone()));
      reg!(s, "ops", "Runbook Engine", RunbookEngine::new().with_metrics(m.clone()));
      reg!(s, "ops", "SLA Tracker", SlaTracker::new().with_metrics(m.clone()));
      reg!(s, "ops", "Ticket Integrator", TicketIntegrator::new().with_metrics(m.clone()));
      dom!(d, "ops", "Operations", 6); }
}

// ── Tauri Commands ───────────────────────────────────────────────────────────

#[tauri::command]
pub fn get_status(backend: tauri::State<'_, Arc<SentinelBackend>>) -> StatusResponse {
    let tier = *backend.current_tier.read();
    let visible: Vec<DomainStatus> = backend.domains.iter()
        .map(|d| {
            let accessible = d.tier <= tier;
            DomainStatus {
                domain: d.domain.clone(),
                display_name: d.display_name.clone(),
                enabled: d.enabled && accessible,
                module_count: if accessible { d.module_count } else { 0 },
                tier: d.tier,
            }
        })
        .collect();
    let enabled = visible.iter().filter(|d| d.enabled).count();
    let modules: usize = visible.iter().map(|d| d.module_count).sum();
    let uptime = chrono::Utc::now().timestamp() - backend.start_time;
    StatusResponse { domains: visible, enabled_domains: enabled, total_modules: modules, uptime_secs: uptime, current_tier: tier }
}

#[tauri::command]
pub fn get_alerts(backend: tauri::State<'_, Arc<SentinelBackend>>) -> AlertResponse {
    let alerts = backend.collect_alerts();
    let critical = alerts.iter().filter(|a| a.severity == "Critical").count();
    let high = alerts.iter().filter(|a| a.severity == "High").count();
    let total = alerts.len();
    AlertResponse { alerts, total, critical, high }
}

#[tauri::command]
pub fn get_metrics(backend: tauri::State<'_, Arc<SentinelBackend>>) -> MetricsResponse {
    let r = backend.metrics.report();
    let pid = std::process::id();
    let mut sys = System::new();
    sys.refresh_process(Pid::from_u32(pid));
    let (rss, vms) = sys.process(Pid::from_u32(pid))
        .map(|p| (p.memory(), p.virtual_memory()))
        .unwrap_or((0, 0));
    MetricsResponse {
        total_budget: r.total_budget, total_used: r.total_used,
        utilization_percent: r.utilization_percent,
        process_rss: rss, process_vms: vms,
    }
}

#[tauri::command]
pub fn get_config() -> serde_json::Value {
    serde_json::json!({ "version": "0.1.0", "memory_budget_mb": 512 })
}

#[tauri::command]
pub fn get_tier_info(backend: tauri::State<'_, Arc<SentinelBackend>>) -> TierInfo {
    let current = *backend.current_tier.read();
    let count = |t: Tier| -> (usize, usize) {
        let doms: Vec<_> = backend.domains.iter().filter(|d| d.tier <= t).collect();
        let mods: usize = doms.iter().map(|d| d.module_count).sum();
        (doms.len(), mods)
    };
    let (fd, fm) = count(Tier::Free);
    let (pd, pm) = count(Tier::Pro);
    let (ed, em) = count(Tier::Enterprise);
    TierInfo {
        current,
        tiers: vec![
            TierDetail {
                tier: Tier::Free, name: "Community Shield".into(), price: "$0".into(),
                domains: fd, modules: fm,
                features: vec!["5 endpoints".into(), "7-day retention".into(), "Personal protection".into(), "Basic alerts".into()],
            },
            TierDetail {
                tier: Tier::Pro, name: "Pro".into(), price: "$29/user/mo".into(),
                domains: pd, modules: pm,
                features: vec!["50 endpoints".into(), "30-day retention".into(), "AI remediation advice".into(), "Team dashboard".into(), "Webhook integrations".into(), "SOC 2 reports".into()],
            },
            TierDetail {
                tier: Tier::Enterprise, name: "Enterprise".into(), price: "$99/user/mo".into(),
                domains: ed, modules: em,
                features: vec!["Unlimited endpoints".into(), "Unlimited retention".into(), "Auto-remediation".into(), "Custom compliance".into(), "API access".into(), "On-prem deploy".into(), "Priority SLA".into()],
            },
        ],
    }
}

#[tauri::command]
pub fn set_tier(backend: tauri::State<'_, Arc<SentinelBackend>>, tier: Tier) -> TierInfo {
    *backend.current_tier.write() = tier;
    log::info!("Tier changed to {:?}", tier);
    get_tier_info(backend)
}

#[tauri::command]
pub fn scan_local_ai() -> serde_json::Value {
    use sentinel_ai::local_ai_discovery::LocalAiDiscovery;
    let scanner = LocalAiDiscovery::new();
    let tools = scanner.scan();
    let summary = scanner.summary();
    serde_json::json!({
        "tools": tools,
        "summary": summary,
    })
}

// ── Plan Review Engine ──────────────────────────────────────────────────────

use sentinel_ai::plan_review_engine::{
    PlanReviewEngine, AgentPlan, PlanReview, PlanAction,
};

#[tauri::command]
pub fn review_plan(
    engine: tauri::State<'_, Arc<PlanReviewEngine>>,
    plan: AgentPlan,
) -> serde_json::Value {
    let cached = engine.cached_verdict(&plan.agent_name, &plan.stated_goal);
    let review = engine.review_plan(&plan);
    let is_dup = engine.is_duplicate_plan(&plan.plan_id);
    serde_json::json!({
        "review": review,
        "is_duplicate": is_dup,
        "cached_verdict": cached,
    })
}

#[tauri::command]
pub fn approve_plan(
    engine: tauri::State<'_, Arc<PlanReviewEngine>>,
    agent: String,
    action: PlanAction,
    target: String,
    approved: bool,
) -> serde_json::Value {
    engine.record_approval(&agent, action, &target, approved);
    serde_json::json!({
        "recorded": true,
        "agent": agent,
        "action": format!("{:?}", action),
        "approved": approved,
    })
}

#[tauri::command]
pub fn get_plan_review_stats(
    engine: tauri::State<'_, Arc<PlanReviewEngine>>,
) -> serde_json::Value {
    serde_json::json!({
        "total_reviews": engine.review_count(),
        "total_critical": engine.critical_count(),
        "total_denied": engine.denied_count(),
        "enabled": engine.is_enabled(),
        "risk_checkpoints": engine.risk_checkpoint_count(),
        "statistics": engine.review_statistics(),
    })
}

#[tauri::command]
pub fn get_plan_review_alerts(
    engine: tauri::State<'_, Arc<PlanReviewEngine>>,
) -> Vec<sentinel_ai::types::AiAlert> {
    engine.alerts()
}

#[tauri::command]
pub fn get_plan_review_history(
    engine: tauri::State<'_, Arc<PlanReviewEngine>>,
    limit: Option<usize>,
) -> Vec<PlanReview> {
    engine.recent_reviews(limit.unwrap_or(25).min(500))
}

#[tauri::command]
pub fn get_plan_risk_matrix(
    engine: tauri::State<'_, Arc<PlanReviewEngine>>,
) -> Vec<serde_json::Value> {
    engine.risk_matrix_entries().into_iter().map(|(agent, action, count)| {
        serde_json::json!({ "agent": agent, "action": action, "count": count })
    }).collect()
}

#[tauri::command]
pub fn get_plan_approval_patterns(
    engine: tauri::State<'_, Arc<PlanReviewEngine>>,
) -> Vec<serde_json::Value> {
    engine.approval_patterns().into_iter().map(|(agent, pattern, count)| {
        serde_json::json!({ "agent": agent, "pattern": pattern, "approved_count": count })
    }).collect()
}

#[tauri::command]
pub fn set_plan_review_enabled(
    engine: tauri::State<'_, Arc<PlanReviewEngine>>,
    enabled: bool,
) -> bool {
    engine.set_enabled(enabled);
    log::info!("Plan Review Engine enabled: {}", enabled);
    enabled
}

// ── Response Integrity Analyzer Commands ─────────────────────────────────

use sentinel_ai::response_integrity_analyzer::{
    ResponseIntegrityAnalyzer, LlmResponse, ResponseAnalysis,
};

#[tauri::command]
pub fn analyze_response(
    analyzer: tauri::State<'_, Arc<ResponseIntegrityAnalyzer>>,
    response: LlmResponse,
) -> ResponseAnalysis {
    analyzer.analyze_response(&response)
}

#[tauri::command]
pub fn get_ria_stats(
    analyzer: tauri::State<'_, Arc<ResponseIntegrityAnalyzer>>,
) -> serde_json::Value {
    let stats = analyzer.integrity_statistics();
    serde_json::json!({
        "total_analyzed": analyzer.analyzed_count(),
        "total_hostile": analyzer.hostile_count(),
        "total_compromised": analyzer.compromised_count(),
        "total_findings": stats.total_findings,
        "total_clean": stats.total_clean,
        "total_suspicious": stats.total_suspicious,
        "stego_detections": stats.stego_detections,
        "data_leak_detections": stats.data_leak_detections,
        "poisoned_artifact_detections": stats.poisoned_artifact_detections,
        "malicious_code_detections": stats.malicious_code_detections,
        "hidden_instruction_detections": stats.hidden_instruction_detections,
        "unique_models": stats.unique_models.len(),
        "enabled": analyzer.is_enabled(),
    })
}

#[tauri::command]
pub fn get_ria_alerts(
    analyzer: tauri::State<'_, Arc<ResponseIntegrityAnalyzer>>,
) -> Vec<sentinel_ai::types::AiAlert> {
    analyzer.alerts()
}

#[tauri::command]
pub fn get_ria_history(
    analyzer: tauri::State<'_, Arc<ResponseIntegrityAnalyzer>>,
    limit: Option<usize>,
) -> Vec<ResponseAnalysis> {
    analyzer.recent_analyses(limit.unwrap_or(25).min(500))
}

#[tauri::command]
pub fn get_ria_finding_matrix(
    analyzer: tauri::State<'_, Arc<ResponseIntegrityAnalyzer>>,
) -> Vec<serde_json::Value> {
    analyzer.finding_matrix_entries().into_iter().map(|(model, category, count)| {
        serde_json::json!({ "model": model, "category": category, "count": count })
    }).collect()
}

#[tauri::command]
pub fn set_ria_enabled(
    analyzer: tauri::State<'_, Arc<ResponseIntegrityAnalyzer>>,
    enabled: bool,
) -> bool {
    analyzer.set_enabled(enabled);
    log::info!("Response Integrity Analyzer enabled: {}", enabled);
    enabled
}

// ── Remediation Engine (Pro-tier LLM-powered advice) ─────────────────────

use sentinel_endpoint::remediation::{RemediationEngine, RemediationRequest};

#[tauri::command]
pub async fn get_remediation(
    backend: tauri::State<'_, Arc<SentinelBackend>>,
    user_store: tauri::State<'_, Arc<crate::auth::UserStore>>,
    engine: tauri::State<'_, Arc<RemediationEngine>>,
    severity: String,
    component: String,
    title: String,
    details: String,
) -> Result<serde_json::Value, String> {
    let tier = *backend.current_tier.read();
    if tier < Tier::Pro {
        return Ok(serde_json::json!({
            "gated": true,
            "message": "AI-powered remediation advice is a Pro feature. Upgrade to unlock step-by-step fix instructions for every alert.",
            "required_tier": "Pro",
        }));
    }
    let auth_state = user_store.get_auth_state();
    let email = match auth_state.user {
        Some(ref u) => u.email.clone(),
        None => return Err("Not authenticated".into()),
    };
    let req = RemediationRequest { severity, component, title, details };
    let resp = engine.generate(&req, &email).await;
    Ok(serde_json::json!({
        "gated": false,
        "advice": resp.advice,
        "cached": resp.cached,
        "model": resp.model,
        "generated_at": resp.generated_at,
    }))
}

#[tauri::command]
pub fn get_remediation_stats(
    engine: tauri::State<'_, Arc<RemediationEngine>>,
) -> serde_json::Value {
    engine.stats()
}
