use sentinel_core::MemoryMetrics;
use std::sync::Arc;
use parking_lot::RwLock;
use tracing::info;
use sentinel_core::config_loader::SentinelConfig;

#[derive(Debug, Clone, serde::Serialize)]
pub struct UnifiedAlert {
    pub timestamp: i64, pub severity: String, pub domain: String,
    pub component: String, pub title: String, pub details: String,
}

pub struct ComponentEntry {
    pub domain: String, pub name: String,
    pub get_alerts: Box<dyn Fn() -> Vec<UnifiedAlert> + Send + Sync>,
}

pub struct SecurityStack {
    pub components: Vec<ComponentEntry>,
    pub metrics: MemoryMetrics,
    pub domain_status: Arc<RwLock<Vec<DomainStatus>>>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DomainStatus {
    pub domain: String, pub display_name: String, pub enabled: bool, pub module_count: usize,
}

impl SecurityStack {
    pub fn collect_alerts(&self) -> Vec<UnifiedAlert> {
        let mut all = Vec::new();
        for c in &self.components { all.extend((c.get_alerts)()); }
        all.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        all.truncate(500);
        all
    }
    pub fn domain_statuses(&self) -> Vec<DomainStatus> { self.domain_status.read().clone() }
}

// Register module with standard alert fields (timestamp, severity, component, title, details)
macro_rules! reg {
    ($c:expr, $d:expr, $n:expr, $mod:expr) => {{
        let a = Arc::new($mod); let r = a.clone();
        $c.push(ComponentEntry { domain: $d.into(), name: $n.into(),
            get_alerts: Box::new(move || {
                r.alerts().into_iter().map(|a| UnifiedAlert {
                    timestamp: a.timestamp, severity: format!("{:?}", a.severity),
                    domain: $d.into(), component: a.component, title: a.title, details: a.details,
                }).collect()
            }),
        });
    }};
}

macro_rules! dom {
    ($s:expr, $d:expr, $dn:expr, $e:expr, $c:expr) => {
        $s.push(DomainStatus { domain: $d.into(), display_name: $dn.into(), enabled: $e, module_count: $c });
    };
}

pub fn bootstrap(config: &SentinelConfig, metrics: MemoryMetrics) -> SecurityStack {
    let mut c: Vec<ComponentEntry> = Vec::new();
    let mut s: Vec<DomainStatus> = Vec::new();
    let m = metrics.clone();

    // 1. Network (custom closures — alert types lack component/title fields)
    if config.network.enabled {
        use sentinel_network::arp_guard::ArpGuard;
        use sentinel_network::firewall::Firewall;
        {
            let a = Arc::new(ArpGuard::new().with_metrics(m.clone())); let r = a.clone();
            c.push(ComponentEntry { domain: "network".into(), name: "ARP Guard".into(),
                get_alerts: Box::new(move || {
                    r.alerts().into_iter().map(|a| UnifiedAlert {
                        timestamp: a.timestamp, severity: format!("{:?}", a.severity),
                        domain: "network".into(), component: "arp_guard".into(),
                        title: format!("ARP {:?}", a.alert_type),
                        details: a.details,
                    }).collect()
                }),
            });
        }
        {
            let a = Arc::new(Firewall::new().with_metrics(m.clone())); let r = a.clone();
            c.push(ComponentEntry { domain: "network".into(), name: "Firewall".into(),
                get_alerts: Box::new(move || {
                    r.alerts().into_iter().map(|a| UnifiedAlert {
                        timestamp: a.timestamp, severity: format!("{:?}", a.severity),
                        domain: "network".into(), component: "firewall".into(),
                        title: a.rule_name.clone(),
                        details: a.message.clone(),
                    }).collect()
                }),
            });
        }
        dom!(s, "network", "Network Security", true, 2);
    } else { dom!(s, "network", "Network Security", false, 0); }

    // 2. Endpoint
    if config.endpoint.enabled {
        use sentinel_endpoint::usb_guard::UsbGuard;
        use sentinel_endpoint::ransomware_detect::RansomwareDetector;
        use sentinel_endpoint::app_control::AppControl;
        use sentinel_endpoint::clipboard_monitor::ClipboardMonitor;
        use sentinel_endpoint::download_guard::DownloadGuard;
        use sentinel_endpoint::file_integrity::FileIntegrityMonitor;
        use sentinel_endpoint::kernel_monitor::KernelMonitor;
        use sentinel_endpoint::login_monitor::LoginMonitor;
        use sentinel_endpoint::malware_scanner::MalwareScanner;
        use sentinel_endpoint::privilege_monitor::PrivilegeMonitor;
        use sentinel_endpoint::process_monitor::ProcessMonitor;
        use sentinel_endpoint::registry_monitor::RegistryMonitor;
        use sentinel_endpoint::scheduled_task_monitor::ScheduledTaskMonitor;
        use sentinel_endpoint::screen_lock::ScreenLockMonitor;
        reg!(c, "endpoint", "USB Guard", UsbGuard::new().with_metrics(m.clone()));
        reg!(c, "endpoint", "Ransomware Detector", RansomwareDetector::new().with_metrics(m.clone()));
        reg!(c, "endpoint", "App Control", AppControl::new(sentinel_endpoint::app_control::PolicyMode::Denylist).with_metrics(m.clone()));
        reg!(c, "endpoint", "Clipboard Monitor", ClipboardMonitor::new().with_metrics(m.clone()));
        reg!(c, "endpoint", "Download Guard", DownloadGuard::new());
        reg!(c, "endpoint", "File Integrity", FileIntegrityMonitor::new().with_metrics(m.clone()));
        reg!(c, "endpoint", "Kernel Monitor", KernelMonitor::new().with_metrics(m.clone()));
        reg!(c, "endpoint", "Login Monitor", LoginMonitor::new().with_metrics(m.clone()));
        reg!(c, "endpoint", "Malware Scanner", MalwareScanner::new().with_metrics(m.clone()));
        reg!(c, "endpoint", "Privilege Monitor", PrivilegeMonitor::new().with_metrics(m.clone()));
        reg!(c, "endpoint", "Process Monitor", ProcessMonitor::new().with_metrics(m.clone()));
        reg!(c, "endpoint", "Registry Monitor", RegistryMonitor::new().with_metrics(m.clone()));
        reg!(c, "endpoint", "Scheduled Task Monitor", ScheduledTaskMonitor::new().with_metrics(m.clone()));
        reg!(c, "endpoint", "Screen Lock", ScreenLockMonitor::new(300).with_metrics(m.clone()));
        dom!(s, "endpoint", "Endpoint Protection", true, 14);
    } else { dom!(s, "endpoint", "Endpoint Protection", false, 0); }

    // 3. DNS
    if config.dns.enabled {
        use sentinel_dns::dns_filter::DnsFilter;
        use sentinel_dns::dns_sinkhole::DnsSinkhole;
        use sentinel_dns::dns_tunnel_detect::DnsTunnelDetector;
        use sentinel_dns::dns_blocklist::DnsBlocklist;
        use sentinel_dns::dns_rate_limiter::DnsRateLimiter;
        use sentinel_dns::dns_rebind_protect::DnsRebindProtect;
        use sentinel_dns::dnssec_validator::DnssecValidator;
        use sentinel_dns::doh_proxy::DohProxy;
        reg!(c, "dns", "DNS Filter", DnsFilter::new().with_metrics(m.clone()));
        reg!(c, "dns", "DNS Sinkhole", DnsSinkhole::new("0.0.0.0").with_metrics(m.clone()));
        reg!(c, "dns", "DNS Tunnel Detector", DnsTunnelDetector::new().with_metrics(m.clone()));
        reg!(c, "dns", "DNS Blocklist", DnsBlocklist::new().with_metrics(m.clone()));
        reg!(c, "dns", "DNS Rate Limiter", DnsRateLimiter::new(1000, 60).with_metrics(m.clone()));
        reg!(c, "dns", "DNS Rebind Protect", DnsRebindProtect::new().with_metrics(m.clone()));
        reg!(c, "dns", "DNSSEC Validator", DnssecValidator::new(true).with_metrics(m.clone()));
        reg!(c, "dns", "DoH Proxy", DohProxy::new(false).with_metrics(m.clone()));
        dom!(s, "dns", "DNS Security", true, 8);
    } else { dom!(s, "dns", "DNS Security", false, 0); }

    // 4. Email
    if config.email.enabled {
        use sentinel_email::spam_filter::SpamFilter;
        use sentinel_email::attachment_scanner::AttachmentScanner;
        use sentinel_email::dkim_validator::DkimValidator;
        use sentinel_email::dlp_scanner::DlpScanner;
        use sentinel_email::dmarc_enforcer::DmarcEnforcer;
        use sentinel_email::email_encrypt::EmailEncrypt;
        use sentinel_email::email_rate_limiter::EmailRateLimiter;
        use sentinel_email::header_analyzer::HeaderAnalyzer;
        use sentinel_email::link_analyzer::LinkAnalyzer;
        use sentinel_email::phishing_detect::PhishingDetector;
        use sentinel_email::quarantine::QuarantineManager;
        use sentinel_email::spf_checker::SpfChecker;
        reg!(c, "email", "Spam Filter", SpamFilter::new(0.7).with_metrics(m.clone()));
        reg!(c, "email", "Attachment Scanner", AttachmentScanner::new().with_metrics(m.clone()));
        reg!(c, "email", "DKIM Validator", DkimValidator::new().with_metrics(m.clone()));
        reg!(c, "email", "DLP Scanner", DlpScanner::new().with_metrics(m.clone()));
        reg!(c, "email", "DMARC Enforcer", DmarcEnforcer::new().with_metrics(m.clone()));
        reg!(c, "email", "Email Encrypt", EmailEncrypt::new().with_metrics(m.clone()));
        reg!(c, "email", "Email Rate Limiter", EmailRateLimiter::new(100, 60).with_metrics(m.clone()));
        reg!(c, "email", "Header Analyzer", HeaderAnalyzer::new().with_metrics(m.clone()));
        reg!(c, "email", "Link Analyzer", LinkAnalyzer::new().with_metrics(m.clone()));
        reg!(c, "email", "Phishing Detector", PhishingDetector::new().with_metrics(m.clone()));
        reg!(c, "email", "Quarantine", QuarantineManager::new().with_metrics(m.clone()));
        reg!(c, "email", "SPF Checker", SpfChecker::new().with_metrics(m.clone()));
        dom!(s, "email", "Email Security", true, 12);
    } else { dom!(s, "email", "Email Security", false, 0); }

    // 5. Identity
    if config.identity.enabled {
        use sentinel_identity::auth_manager::AuthManager;
        use sentinel_identity::session_manager::SessionManager;
        use sentinel_identity::mfa_engine::MfaEngine;
        use sentinel_identity::rbac_engine::RbacEngine;
        use sentinel_identity::credential_store::CredentialStore;
        use sentinel_identity::identity_federation::IdentityFederation;
        use sentinel_identity::privilege_access::PrivilegeAccessManager;
        use sentinel_identity::sso_provider::SsoManager;
        use sentinel_identity::user_behavior::UserBehaviorAnalytics;
        let mf = config.identity.settings.get("max_failed_attempts").and_then(|v| v.as_integer()).unwrap_or(5) as u32;
        let lo = config.identity.settings.get("lockout_duration_secs").and_then(|v| v.as_integer()).unwrap_or(900);
        let to = config.identity.settings.get("session_timeout_secs").and_then(|v| v.as_integer()).unwrap_or(3600);
        reg!(c, "identity", "Auth Manager", AuthManager::new(mf, lo).with_metrics(m.clone()));
        reg!(c, "identity", "Session Manager", SessionManager::new(100, to).with_metrics(m.clone()));
        reg!(c, "identity", "MFA Engine", MfaEngine::new().with_metrics(m.clone()));
        reg!(c, "identity", "RBAC Engine", RbacEngine::new().with_metrics(m.clone()));
        reg!(c, "identity", "Credential Store", CredentialStore::new(90).with_metrics(m.clone()));
        reg!(c, "identity", "Identity Federation", IdentityFederation::new().with_metrics(m.clone()));
        reg!(c, "identity", "Privilege Access", PrivilegeAccessManager::new(3600).with_metrics(m.clone()));
        reg!(c, "identity", "SSO Provider", SsoManager::new().with_metrics(m.clone()));
        reg!(c, "identity", "User Behavior", UserBehaviorAnalytics::new(0.8).with_metrics(m.clone()));
        dom!(s, "identity", "Identity & Access", true, 9);
    } else { dom!(s, "identity", "Identity & Access", false, 0); }

    // 6. SIEM (custom closure — SiemAlert has rule_name instead of component)
    {
        use sentinel_siem::correlation_engine::CorrelationEngine;
        let a = Arc::new(CorrelationEngine::new().with_metrics(m.clone())); let r = a.clone();
        c.push(ComponentEntry { domain: "siem".into(), name: "Correlation Engine".into(),
            get_alerts: Box::new(move || {
                r.alerts().into_iter().map(|a| UnifiedAlert {
                    timestamp: a.timestamp, severity: format!("{:?}", a.severity),
                    domain: "siem".into(), component: "correlation_engine".into(),
                    title: a.title, details: a.details,
                }).collect()
            }),
        });
        dom!(s, "siem", "SIEM", true, 1);
    }

    // 7. IoT
    if config.iot.enabled {
        use sentinel_iot::device_registry::DeviceRegistry;
        use sentinel_iot::anomaly_detector::AnomalyDetector;
        use sentinel_iot::device_auth::DeviceAuth;
        use sentinel_iot::device_policy::DevicePolicyEngine;
        use sentinel_iot::firmware_validator::FirmwareValidator;
        use sentinel_iot::network_segmenter::NetworkSegmenter;
        use sentinel_iot::ota_manager::OtaManager;
        use sentinel_iot::protocol_analyzer::ProtocolAnalyzer;
        use sentinel_iot::telemetry_monitor::TelemetryMonitor;
        reg!(c, "iot", "Device Registry", DeviceRegistry::new().with_metrics(m.clone()));
        reg!(c, "iot", "Anomaly Detector", AnomalyDetector::new(0.8).with_metrics(m.clone()));
        reg!(c, "iot", "Device Auth", DeviceAuth::new().with_metrics(m.clone()));
        reg!(c, "iot", "Device Policy", DevicePolicyEngine::new().with_metrics(m.clone()));
        reg!(c, "iot", "Firmware Validator", FirmwareValidator::new().with_metrics(m.clone()));
        reg!(c, "iot", "Network Segmenter", NetworkSegmenter::new().with_metrics(m.clone()));
        reg!(c, "iot", "OTA Manager", OtaManager::new().with_metrics(m.clone()));
        reg!(c, "iot", "Protocol Analyzer", ProtocolAnalyzer::new().with_metrics(m.clone()));
        reg!(c, "iot", "Telemetry Monitor", TelemetryMonitor::new().with_metrics(m.clone()));
        dom!(s, "iot", "IoT Security", true, 9);
    } else { dom!(s, "iot", "IoT Security", false, 0); }

    // 8. Data
    if config.data.enabled {
        use sentinel_data::tokenizer::Tokenizer;
        use sentinel_data::dlp_scanner::DlpScanner;
        use sentinel_data::access_controller::AccessController;
        use sentinel_data::backup_manager::BackupManager;
        use sentinel_data::classification_engine::ClassificationEngine;
        use sentinel_data::data_lineage::DataLineage;
        use sentinel_data::encryption_engine::EncryptionEngine;
        use sentinel_data::integrity_checker::IntegrityChecker;
        use sentinel_data::key_manager::KeyManager;
        use sentinel_data::masking_engine::MaskingEngine;
        reg!(c, "data", "Tokenizer", Tokenizer::new().with_metrics(m.clone()));
        reg!(c, "data", "DLP Scanner", DlpScanner::new().with_metrics(m.clone()));
        reg!(c, "data", "Access Controller", AccessController::new().with_metrics(m.clone()));
        reg!(c, "data", "Backup Manager", BackupManager::new().with_metrics(m.clone()));
        reg!(c, "data", "Classification Engine", ClassificationEngine::new().with_metrics(m.clone()));
        reg!(c, "data", "Data Lineage", DataLineage::new().with_metrics(m.clone()));
        reg!(c, "data", "Encryption Engine", EncryptionEngine::new().with_metrics(m.clone()));
        reg!(c, "data", "Integrity Checker", IntegrityChecker::new().with_metrics(m.clone()));
        reg!(c, "data", "Key Manager", KeyManager::new().with_metrics(m.clone()));
        reg!(c, "data", "Masking Engine", MaskingEngine::new().with_metrics(m.clone()));
        dom!(s, "data", "Data Protection", true, 10);
    } else { dom!(s, "data", "Data Protection", false, 0); }

    // 9. Threat Intel
    if config.threat_intel.enabled {
        use sentinel_threat_intel::stix_parser::StixParser;
        use sentinel_threat_intel::enrichment_engine::EnrichmentEngine;
        use sentinel_threat_intel::feed_manager::FeedManager;
        use sentinel_threat_intel::ioc_store::IocStore;
        use sentinel_threat_intel::reputation_engine::ReputationEngine;
        use sentinel_threat_intel::sharing_hub::SharingHub;
        use sentinel_threat_intel::threat_correlator::ThreatCorrelator;
        reg!(c, "threat_intel", "STIX Parser", StixParser::new().with_metrics(m.clone()));
        reg!(c, "threat_intel", "Enrichment Engine", EnrichmentEngine::new().with_metrics(m.clone()));
        reg!(c, "threat_intel", "Feed Manager", FeedManager::new().with_metrics(m.clone()));
        reg!(c, "threat_intel", "IOC Store", IocStore::new().with_metrics(m.clone()));
        reg!(c, "threat_intel", "Reputation Engine", ReputationEngine::new().with_metrics(m.clone()));
        reg!(c, "threat_intel", "Sharing Hub", SharingHub::new().with_metrics(m.clone()));
        reg!(c, "threat_intel", "Threat Correlator", ThreatCorrelator::new(2).with_metrics(m.clone()));
        dom!(s, "threat_intel", "Threat Intelligence", true, 7);
    } else { dom!(s, "threat_intel", "Threat Intelligence", false, 0); }

    // 10. Forensics
    if config.forensics.enabled {
        use sentinel_forensics::evidence_collector::EvidenceCollector;
        use sentinel_forensics::timeline_builder::TimelineBuilder;
        use sentinel_forensics::artifact_extractor::ArtifactExtractor;
        use sentinel_forensics::report_writer::ReportWriter;
        use sentinel_forensics::chain_of_custody::ChainOfCustody;
        use sentinel_forensics::disk_imager::DiskImager;
        use sentinel_forensics::memory_analyzer::MemoryAnalyzer;
        use sentinel_forensics::memory_timeline::MemoryTimeline;
        use sentinel_forensics::provenance_graph::ProvenanceGraph;
        reg!(c, "forensics", "Evidence Collector", EvidenceCollector::new().with_metrics(m.clone()));
        reg!(c, "forensics", "Timeline Builder", TimelineBuilder::new().with_metrics(m.clone()));
        reg!(c, "forensics", "Artifact Extractor", ArtifactExtractor::new().with_metrics(m.clone()));
        reg!(c, "forensics", "Report Writer", ReportWriter::new().with_metrics(m.clone()));
        reg!(c, "forensics", "Chain of Custody", ChainOfCustody::new().with_metrics(m.clone()));
        reg!(c, "forensics", "Disk Imager", DiskImager::new().with_metrics(m.clone()));
        reg!(c, "forensics", "Memory Analyzer", MemoryAnalyzer::new().with_metrics(m.clone()));
        reg!(c, "forensics", "Memory Timeline", MemoryTimeline::new().with_metrics(m.clone()));
        reg!(c, "forensics", "Provenance Graph", ProvenanceGraph::new().with_metrics(m.clone()));
        dom!(s, "forensics", "Digital Forensics", true, 9);
    } else { dom!(s, "forensics", "Digital Forensics", false, 0); }

    // 11. Vuln
    if config.vuln.enabled {
        use sentinel_vuln::cve_database::CveDatabase;
        use sentinel_vuln::exploit_detector::ExploitDetector;
        use sentinel_vuln::patch_manager::PatchManager;
        use sentinel_vuln::remediation_engine::RemediationEngine;
        use sentinel_vuln::risk_scorer::RiskScorer;
        use sentinel_vuln::scanner::VulnScanner;
        reg!(c, "vuln", "CVE Database", CveDatabase::new().with_metrics(m.clone()));
        reg!(c, "vuln", "Exploit Detector", ExploitDetector::new().with_metrics(m.clone()));
        reg!(c, "vuln", "Patch Manager", PatchManager::new().with_metrics(m.clone()));
        reg!(c, "vuln", "Remediation Engine", RemediationEngine::new().with_metrics(m.clone()));
        reg!(c, "vuln", "Risk Scorer", RiskScorer::new().with_metrics(m.clone()));
        reg!(c, "vuln", "Vuln Scanner", VulnScanner::new().with_metrics(m.clone()));
        dom!(s, "vuln", "Vulnerability Mgmt", true, 6);
    } else { dom!(s, "vuln", "Vulnerability Mgmt", false, 0); }

    // 12. Web
    if config.web.enabled {
        use sentinel_web::waf_engine::WafEngine;
        use sentinel_web::bot_detector::BotDetector;
        use sentinel_web::content_scanner::ContentScanner;
        use sentinel_web::session_protector::SessionProtector;
        use sentinel_web::ssl_inspector::SslInspector;
        reg!(c, "web", "WAF Engine", WafEngine::new().with_metrics(m.clone()));
        reg!(c, "web", "Bot Detector", BotDetector::new(100).with_metrics(m.clone()));
        reg!(c, "web", "Content Scanner", ContentScanner::new().with_metrics(m.clone()));
        reg!(c, "web", "Session Protector", SessionProtector::new().with_metrics(m.clone()));
        reg!(c, "web", "SSL Inspector", SslInspector::new().with_metrics(m.clone()));
        dom!(s, "web", "Web App Security", true, 5);
    } else { dom!(s, "web", "Web App Security", false, 0); }

    // 13. Container
    if config.container.enabled {
        use sentinel_container::image_scanner::ImageScanner;
        use sentinel_container::runtime_monitor::RuntimeMonitor;
        use sentinel_container::secret_manager::SecretManager;
        use sentinel_container::policy_enforcer::PolicyEnforcer;
        use sentinel_container::registry_guard::RegistryGuard;
        reg!(c, "container", "Image Scanner", ImageScanner::new().with_metrics(m.clone()));
        reg!(c, "container", "Runtime Monitor", RuntimeMonitor::new(0.9).with_metrics(m.clone()));
        reg!(c, "container", "Secret Manager", SecretManager::new().with_metrics(m.clone()));
        reg!(c, "container", "Policy Enforcer", PolicyEnforcer::new().with_metrics(m.clone()));
        reg!(c, "container", "Registry Guard", RegistryGuard::new().with_metrics(m.clone()));
        dom!(s, "container", "Container Security", true, 5);
    } else { dom!(s, "container", "Container Security", false, 0); }

    // 14. Supply Chain
    if config.supply_chain.enabled {
        use sentinel_supply_chain::sbom_manager::SbomManager;
        use sentinel_supply_chain::license_checker::LicenseChecker;
        use sentinel_supply_chain::artifact_verifier::ArtifactVerifier;
        use sentinel_supply_chain::build_integrity::BuildIntegrity;
        use sentinel_supply_chain::dependency_scanner::DependencyScanner;
        reg!(c, "supply_chain", "SBOM Manager", SbomManager::new());
        reg!(c, "supply_chain", "License Checker", LicenseChecker::new());
        reg!(c, "supply_chain", "Artifact Verifier", ArtifactVerifier::new().with_metrics(m.clone()));
        reg!(c, "supply_chain", "Build Integrity", BuildIntegrity::new().with_metrics(m.clone()));
        reg!(c, "supply_chain", "Dependency Scanner", DependencyScanner::new().with_metrics(m.clone()));
        dom!(s, "supply_chain", "Supply Chain", true, 5);
    } else { dom!(s, "supply_chain", "Supply Chain", false, 0); }

    // 15. Compliance
    if config.compliance.enabled {
        use sentinel_compliance::policy_engine::PolicyEngine;
        use sentinel_compliance::audit_logger::AuditLogger;
        use sentinel_compliance::report_generator::ReportGenerator;
        use sentinel_compliance::control_mapper::ControlMapper;
        use sentinel_compliance::gap_analyzer::GapAnalyzer;
        reg!(c, "compliance", "Policy Engine", PolicyEngine::new().with_metrics(m.clone()));
        reg!(c, "compliance", "Audit Logger", AuditLogger::new().with_metrics(m.clone()));
        reg!(c, "compliance", "Report Generator", ReportGenerator::new().with_metrics(m.clone()));
        reg!(c, "compliance", "Control Mapper", ControlMapper::new().with_metrics(m.clone()));
        reg!(c, "compliance", "Gap Analyzer", GapAnalyzer::new().with_metrics(m.clone()));
        dom!(s, "compliance", "Compliance", true, 5);
    } else { dom!(s, "compliance", "Compliance", false, 0); }

    // 16. Privacy
    if config.privacy.enabled {
        use sentinel_privacy::consent_manager::ConsentManager;
        use sentinel_privacy::retention_enforcer::RetentionEnforcer;
        use sentinel_privacy::dsar_handler::DsarHandler;
        use sentinel_privacy::pii_scanner::PiiScanner;
        use sentinel_privacy::anonymizer::Anonymizer;
        use sentinel_privacy::tracker_blocker::TrackerBlocker;
        reg!(c, "privacy", "Consent Manager", ConsentManager::new());
        reg!(c, "privacy", "Retention Enforcer", RetentionEnforcer::new());
        reg!(c, "privacy", "DSAR Handler", DsarHandler::new());
        reg!(c, "privacy", "PII Scanner", PiiScanner::new());
        reg!(c, "privacy", "Anonymizer", Anonymizer::new());
        reg!(c, "privacy", "Tracker Blocker", TrackerBlocker::new().with_metrics(m.clone()));
        dom!(s, "privacy", "Privacy", true, 6);
    } else { dom!(s, "privacy", "Privacy", false, 0); }

    // 17. AI Agent Security (55 modules — most comprehensive AI security layer in existence)
    if config.ai.enabled {
        // ── Imports: Core AI monitoring ─────────────────────────────────────
        use sentinel_ai::shadow_ai_detector::ShadowAiDetector;
        use sentinel_ai::api_key_monitor::ApiKeyMonitor;
        use sentinel_ai::prompt_guard::PromptGuard;
        use sentinel_ai::output_filter::OutputFilter;
        use sentinel_ai::model_scanner::ModelScanner;
        use sentinel_ai::data_poisoning_detector::DataPoisoningDetector;
        use sentinel_ai::local_sandbox::LocalSandbox;
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
        // ── Imports: Pre-inference defense ──────────────────────────────────
        use sentinel_ai::semantic_firewall::SemanticFirewall;
        use sentinel_ai::indirect_injection_scanner::IndirectInjectionScanner;
        use sentinel_ai::multi_turn_tracker::MultiTurnTracker;
        use sentinel_ai::token_smuggling_detector::TokenSmugglingDetector;
        use sentinel_ai::context_window_stuffing_guard::ContextWindowStuffingGuard;
        use sentinel_ai::instruction_hierarchy_enforcer::InstructionHierarchyEnforcer;
        use sentinel_ai::capability_probe_detector::CapabilityProbeDetector;
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
        // ── Imports: NEW — additional AI modules ─────────────────────────────
        use sentinel_ai::local_ai_discovery::LocalAiDiscovery;
        use sentinel_ai::plan_review_engine::PlanReviewEngine;
        use sentinel_ai::response_integrity_analyzer::ResponseIntegrityAnalyzer;

        // ── Registration: Core AI monitoring ───────────────────────────────
        reg!(c, "ai", "Shadow AI Detector", ShadowAiDetector::new().with_metrics(m.clone()));
        reg!(c, "ai", "API Key Monitor", ApiKeyMonitor::new().with_metrics(m.clone()));
        reg!(c, "ai", "Prompt Guard", PromptGuard::new());
        reg!(c, "ai", "Output Filter", OutputFilter::new());
        reg!(c, "ai", "Model Scanner", ModelScanner::new());
        reg!(c, "ai", "Data Poisoning Detector", DataPoisoningDetector::new(0.7));
        reg!(c, "ai", "Local Sandbox", LocalSandbox::new());
        // ── Registration: Pre-inference defense ────────────────────────────
        reg!(c, "ai", "Semantic Firewall", SemanticFirewall::new());
        reg!(c, "ai", "Indirect Injection Scanner", IndirectInjectionScanner::new());
        reg!(c, "ai", "Multi-Turn Tracker", MultiTurnTracker::new());
        reg!(c, "ai", "Token Smuggling Detector", TokenSmugglingDetector::new());
        reg!(c, "ai", "Context Window Stuffing Guard", ContextWindowStuffingGuard::new());
        reg!(c, "ai", "Instruction Hierarchy Enforcer", InstructionHierarchyEnforcer::new());
        reg!(c, "ai", "Capability Probe Detector", CapabilityProbeDetector::new());
        // ── Registration: Agent runtime security ───────────────────────────
        reg!(c, "ai", "Tool Call Validator", ToolCallValidator::new());
        reg!(c, "ai", "Tool Integrity Verifier", ToolIntegrityVerifier::new());
        reg!(c, "ai", "Agent Action Logger", AgentActionLogger::new());
        reg!(c, "ai", "Agent Permission Boundary", AgentPermissionBoundary::new());
        reg!(c, "ai", "Agent Network Fence", AgentNetworkFence::new());
        reg!(c, "ai", "Agent Behavior Baseline", AgentBehaviorBaseline::new());
        reg!(c, "ai", "Agent Session Recorder", AgentSessionRecorder::new());
        reg!(c, "ai", "Agent Cost Monitor", AgentCostMonitor::new());
        reg!(c, "ai", "Agent Identity Attestation", AgentIdentityAttestation::new());
        reg!(c, "ai", "Clipboard Exfil Detector", ClipboardExfilDetector::new());
        reg!(c, "ai", "Multi-Agent Conflict", MultiAgentConflictDetector::new());
        reg!(c, "ai", "Delegation Chain Auditor", DelegationChainAuditor::new());
        reg!(c, "ai", "Cross-Plugin Data Fence", CrossPluginDataFence::new());
        reg!(c, "ai", "Autonomous Agent Containment", AutonomousAgentContainment::new());
        // ── Registration: Post-inference & output ──────────────────────────
        reg!(c, "ai", "Output Watermarker", OutputWatermarker::new());
        reg!(c, "ai", "Hallucination Detector", HallucinationDetector::new());
        reg!(c, "ai", "Conversation State Integrity", ConversationStateIntegrity::new());
        // ── Registration: Continuous monitoring ────────────────────────────
        reg!(c, "ai", "RAG Poisoning Detector", RagPoisoningDetector::new());
        reg!(c, "ai", "MCP Protocol Security", McpProtocolSecurity::new());
        reg!(c, "ai", "Reasoning Trace Auditor", ReasoningTraceAuditor::new());
        reg!(c, "ai", "Memory Poisoning Guard", MemoryPoisoningGuard::new());
        reg!(c, "ai", "Sleeper Agent Detector", SleeperAgentDetector::new());
        reg!(c, "ai", "Goal Drift Monitor", GoalDriftMonitor::new());
        reg!(c, "ai", "Agentic Loop Detector", AgenticLoopDetector::new());
        reg!(c, "ai", "Human-in-the-Loop Enforcer", HumanInTheLoopEnforcer::new());
        reg!(c, "ai", "Model Extraction Guard", ModelExtractionGuard::new());
        reg!(c, "ai", "Adversarial Input Detector", AdversarialInputDetector::new());
        reg!(c, "ai", "AI Supply Chain Attestation", AiSupplyChainAttestation::new());
        reg!(c, "ai", "Security Pipeline", SecurityPipeline::new());
        // ── Registration: NEW Tier 1 — Critical AI defense ─────────────────
        reg!(c, "ai", "System Prompt Guardian", SystemPromptGuardian::new());
        reg!(c, "ai", "Multimodal Injection Scanner", MultimodalInjectionScanner::new());
        reg!(c, "ai", "Jailbreak Classifier", JailbreakClassifier::new());
        reg!(c, "ai", "Training Data Extraction Guard", TrainingDataExtractionGuard::new());
        reg!(c, "ai", "Embedding Space Monitor", EmbeddingSpaceMonitor::new());
        // ── Registration: NEW Tier 2 — Important AI defense ────────────────
        reg!(c, "ai", "Synthetic Content Detector", SyntheticContentDetector::new());
        reg!(c, "ai", "Fine-Tuning Attack Detector", FineTuningAttackDetector::new());
        reg!(c, "ai", "Reward Hacking Detector", RewardHackingDetector::new());
        reg!(c, "ai", "Model Drift Sentinel", ModelDriftSentinel::new());
        // ── Registration: Additional AI modules ─────────────────────────────
        reg!(c, "ai", "Local AI Discovery", LocalAiDiscovery::new());
        reg!(c, "ai", "Plan Review Engine", PlanReviewEngine::new());
        reg!(c, "ai", "Response Integrity Analyzer", ResponseIntegrityAnalyzer::new());
        dom!(s, "ai", "AI Agent Security", true, 58);
    } else { dom!(s, "ai", "AI Agent Security", false, 0); }

    // 18. Deception
    if config.deception.enabled {
        use sentinel_deception::dns_canary::DnsCanary;
        use sentinel_deception::honey_file::HoneyFile;
        use sentinel_deception::attacker_profiler::AttackerProfiler;
        use sentinel_deception::decoy_network::DecoyNetwork;
        use sentinel_deception::honey_token::HoneyTokenManager;
        use sentinel_deception::honeypot_manager::HoneypotManager;
        reg!(c, "deception", "DNS Canary", DnsCanary::new().with_metrics(m.clone()));
        reg!(c, "deception", "Honey File", HoneyFile::new().with_metrics(m.clone()));
        reg!(c, "deception", "Attacker Profiler", AttackerProfiler::new().with_metrics(m.clone()));
        reg!(c, "deception", "Decoy Network", DecoyNetwork::new());
        reg!(c, "deception", "Honey Token", HoneyTokenManager::new());
        reg!(c, "deception", "Honeypot Manager", HoneypotManager::new());
        dom!(s, "deception", "Deception Tech", true, 6);
    } else { dom!(s, "deception", "Deception Tech", false, 0); }

    // 19. Browser
    if config.browser.enabled {
        use sentinel_browser::download_scanner::DownloadScanner;
        use sentinel_browser::cookie_guard::CookieGuard;
        use sentinel_browser::extension_scanner::ExtensionScanner;
        use sentinel_browser::script_analyzer::ScriptAnalyzer;
        use sentinel_browser::url_filter::UrlFilter;
        reg!(c, "browser", "Download Scanner", DownloadScanner::new().with_metrics(m.clone()));
        reg!(c, "browser", "Cookie Guard", CookieGuard::new().with_metrics(m.clone()));
        reg!(c, "browser", "Extension Scanner", ExtensionScanner::new().with_metrics(m.clone()));
        reg!(c, "browser", "Script Analyzer", ScriptAnalyzer::new().with_metrics(m.clone()));
        reg!(c, "browser", "URL Filter", UrlFilter::new().with_metrics(m.clone()));
        dom!(s, "browser", "Browser Security", true, 5);
    } else { dom!(s, "browser", "Browser Security", false, 0); }

    // 20. API
    if config.api.enabled {
        use sentinel_api::graphql_blocker::GraphqlBlocker;
        use sentinel_api::auth_enforcer::AuthEnforcer;
        use sentinel_api::payload_inspector::PayloadInspector;
        use sentinel_api::rate_limiter::RateLimiter;
        use sentinel_api::schema_validator::SchemaValidator;
        reg!(c, "api", "GraphQL Blocker", GraphqlBlocker::new(10).with_metrics(m.clone()));
        reg!(c, "api", "Auth Enforcer", AuthEnforcer::new());
        reg!(c, "api", "Payload Inspector", PayloadInspector::new().with_metrics(m.clone()));
        reg!(c, "api", "Rate Limiter", RateLimiter::new(1000).with_metrics(m.clone()));
        reg!(c, "api", "Schema Validator", SchemaValidator::new().with_metrics(m.clone()));
        dom!(s, "api", "API Security", true, 5);
    } else { dom!(s, "api", "API Security", false, 0); }

    // 21. VPN
    if config.vpn.enabled {
        use sentinel_vpn::tunnel_monitor::TunnelMonitor;
        use sentinel_vpn::split_tunnel::SplitTunnel;
        use sentinel_vpn::leak_detector::LeakDetector;
        use sentinel_vpn::access_controller::AccessController;
        reg!(c, "vpn", "Tunnel Monitor", TunnelMonitor::new());
        reg!(c, "vpn", "Split Tunnel", SplitTunnel::new());
        reg!(c, "vpn", "Leak Detector", LeakDetector::new());
        reg!(c, "vpn", "Access Controller", AccessController::new());
        dom!(s, "vpn", "VPN Security", true, 4);
    } else { dom!(s, "vpn", "VPN Security", false, 0); }

    // 22. Hardware (no with_metrics)
    if config.hardware.enabled {
        use sentinel_hardware::device_guard::DeviceGuard;
        use sentinel_hardware::tpm_manager::TpmManager;
        use sentinel_hardware::secure_boot::SecureBoot;
        use sentinel_hardware::firmware_scanner::FirmwareScanner;
        reg!(c, "hardware", "Device Guard", DeviceGuard::new());
        reg!(c, "hardware", "TPM Manager", TpmManager::new());
        reg!(c, "hardware", "Secure Boot", SecureBoot::new());
        reg!(c, "hardware", "Firmware Scanner", FirmwareScanner::new());
        dom!(s, "hardware", "Hardware Security", true, 4);
    } else { dom!(s, "hardware", "Hardware Security", false, 0); }

    // 23. Exfiltration
    if config.exfiltration.enabled {
        use sentinel_exfiltration::channel_detector::ChannelDetector;
        use sentinel_exfiltration::volume_monitor::VolumeMonitor;
        use sentinel_exfiltration::clipboard_guard::ClipboardGuard;
        use sentinel_exfiltration::watermarker::Watermarker;
        reg!(c, "exfiltration", "Channel Detector", ChannelDetector::new(0.7));
        reg!(c, "exfiltration", "Volume Monitor", VolumeMonitor::new(3.0));
        reg!(c, "exfiltration", "Clipboard Guard", ClipboardGuard::new());
        reg!(c, "exfiltration", "Watermarker", Watermarker::new());
        dom!(s, "exfiltration", "Data Exfiltration", true, 4);
    } else { dom!(s, "exfiltration", "Data Exfiltration", false, 0); }

    // 24. Mgmt
    if config.mgmt.enabled {
        use sentinel_mgmt::health_monitor::HealthMonitor;
        use sentinel_mgmt::alert_feed::AlertFeed;
        use sentinel_mgmt::api_gateway::ApiGateway;
        use sentinel_mgmt::config_manager::ConfigManager;
        use sentinel_mgmt::dashboard::Dashboard;
        use sentinel_mgmt::device_inventory::DeviceInventory;
        use sentinel_mgmt::update_manager::UpdateManager;
        reg!(c, "mgmt", "Health Monitor", HealthMonitor::new().with_metrics(m.clone()));
        reg!(c, "mgmt", "Alert Feed", AlertFeed::new().with_metrics(m.clone()));
        reg!(c, "mgmt", "API Gateway", ApiGateway::new().with_metrics(m.clone()));
        reg!(c, "mgmt", "Config Manager", ConfigManager::new().with_metrics(m.clone()));
        reg!(c, "mgmt", "Dashboard", Dashboard::new().with_metrics(m.clone()));
        reg!(c, "mgmt", "Device Inventory", DeviceInventory::new().with_metrics(m.clone()));
        reg!(c, "mgmt", "Update Manager", UpdateManager::new().with_metrics(m.clone()));
        dom!(s, "mgmt", "Management", true, 7);
    } else { dom!(s, "mgmt", "Management", false, 0); }

    // 25. Self-Protection
    if config.selfprotect.enabled {
        use sentinel_selfprotect::binary_integrity::BinaryIntegrity;
        use sentinel_selfprotect::anti_tampering::AntiTampering;
        use sentinel_selfprotect::config_protection::ConfigProtection;
        use sentinel_selfprotect::secure_updates::SecureUpdates;
        reg!(c, "selfprotect", "Binary Integrity", BinaryIntegrity::new().with_metrics(m.clone()));
        reg!(c, "selfprotect", "Anti-Tampering", AntiTampering::new().with_metrics(m.clone()));
        reg!(c, "selfprotect", "Config Protection", ConfigProtection::new().with_metrics(m.clone()));
        reg!(c, "selfprotect", "Secure Updates", SecureUpdates::new().with_metrics(m.clone()));
        dom!(s, "selfprotect", "Self-Protection", true, 4);
    } else { dom!(s, "selfprotect", "Self-Protection", false, 0); }

    // 26. Phishing
    if config.phishing.enabled {
        use sentinel_phishing::lookalike_domain::LookalikeDomainMonitor;
        use sentinel_phishing::link_scanner::LinkScanner;
        use sentinel_phishing::qr_scanner::QrScanner;
        use sentinel_phishing::vishing_detector::VishingDetector;
        reg!(c, "phishing", "Lookalike Domain", LookalikeDomainMonitor::new().with_metrics(m.clone()));
        reg!(c, "phishing", "Link Scanner", LinkScanner::new().with_metrics(m.clone()));
        reg!(c, "phishing", "QR Scanner", QrScanner::new().with_metrics(m.clone()));
        reg!(c, "phishing", "Vishing Detector", VishingDetector::new().with_metrics(m.clone()));
        dom!(s, "phishing", "Anti-Phishing", true, 4);
    } else { dom!(s, "phishing", "Anti-Phishing", false, 0); }

    // 27. Crypto
    if config.crypto.enabled {
        use sentinel_crypto::tls_auditor::TlsAuditor;
        use sentinel_crypto::ca_monitor::CaMonitor;
        use sentinel_crypto::key_rotation::KeyRotation;
        use sentinel_crypto::quantum_readiness::QuantumReadiness;
        reg!(c, "crypto", "TLS Auditor", TlsAuditor::new().with_metrics(m.clone()));
        reg!(c, "crypto", "CA Monitor", CaMonitor::new().with_metrics(m.clone()));
        reg!(c, "crypto", "Key Rotation", KeyRotation::new().with_metrics(m.clone()));
        reg!(c, "crypto", "Quantum Readiness", QuantumReadiness::new().with_metrics(m.clone()));
        dom!(s, "crypto", "Cryptography", true, 4);
    } else { dom!(s, "crypto", "Cryptography", false, 0); }

    // 28. Resilience
    if config.resilience.enabled {
        use sentinel_resilience::auto_quarantine::AutoQuarantine;
        use sentinel_resilience::kill_switch::KillSwitch;
        use sentinel_resilience::dr_tester::DrTester;
        use sentinel_resilience::rollback_engine::RollbackEngine;
        reg!(c, "resilience", "Auto-Quarantine", AutoQuarantine::new().with_metrics(m.clone()));
        reg!(c, "resilience", "Kill Switch", KillSwitch::new().with_metrics(m.clone()));
        reg!(c, "resilience", "DR Tester", DrTester::new().with_metrics(m.clone()));
        reg!(c, "resilience", "Rollback Engine", RollbackEngine::new().with_metrics(m.clone()));
        dom!(s, "resilience", "Resilience", true, 4);
    } else { dom!(s, "resilience", "Resilience", false, 0); }

    // 29. Mobile
    if config.mobile.enabled {
        use sentinel_mobile::app_permission_auditor::AppPermissionAuditor;
        use sentinel_mobile::network_traffic_monitor::NetworkTrafficMonitor;
        use sentinel_mobile::mdm_lite::MdmLite;
        use sentinel_mobile::rogue_app_store::RogueAppStore;
        use sentinel_mobile::sim_swap_detector::SimSwapDetector;
        reg!(c, "mobile", "App Permission Auditor", AppPermissionAuditor::new().with_metrics(m.clone()));
        reg!(c, "mobile", "Network Traffic Monitor", NetworkTrafficMonitor::new().with_metrics(m.clone()));
        reg!(c, "mobile", "MDM Lite", MdmLite::new().with_metrics(m.clone()));
        reg!(c, "mobile", "Rogue App Store", RogueAppStore::new().with_metrics(m.clone()));
        reg!(c, "mobile", "SIM Swap Detector", SimSwapDetector::new().with_metrics(m.clone()));
        dom!(s, "mobile", "Mobile Security", true, 5);
    } else { dom!(s, "mobile", "Mobile Security", false, 0); }

    // 30. Dark Web
    if config.darkweb.enabled {
        use sentinel_darkweb::domain_reputation::DomainReputationMonitor;
        use sentinel_darkweb::exposed_service_detector::ExposedServiceDetector;
        use sentinel_darkweb::breach_credential_monitor::BreachCredentialMonitor;
        use sentinel_darkweb::ct_watcher::CtWatcher;
        reg!(c, "darkweb", "Domain Reputation", DomainReputationMonitor::new().with_metrics(m.clone()));
        reg!(c, "darkweb", "Exposed Service Detector", ExposedServiceDetector::new().with_metrics(m.clone()));
        reg!(c, "darkweb", "Breach Credential Monitor", BreachCredentialMonitor::new().with_metrics(m.clone()));
        reg!(c, "darkweb", "CT Watcher", CtWatcher::new().with_metrics(m.clone()));
        dom!(s, "darkweb", "Dark Web Intel", true, 4);
    } else { dom!(s, "darkweb", "Dark Web Intel", false, 0); }

    // 31. OT/ICS
    if config.ot.enabled {
        use sentinel_ot::scada_monitor::ScadaMonitor;
        use sentinel_ot::serial_monitor::SerialMonitor;
        use sentinel_ot::plc_integrity::PlcIntegrity;
        use sentinel_ot::safety_validator::SafetyValidator;
        reg!(c, "ot", "SCADA Monitor", ScadaMonitor::new().with_metrics(m.clone()));
        reg!(c, "ot", "Serial Monitor", SerialMonitor::new().with_metrics(m.clone()));
        reg!(c, "ot", "PLC Integrity", PlcIntegrity::new().with_metrics(m.clone()));
        reg!(c, "ot", "Safety Validator", SafetyValidator::new().with_metrics(m.clone()));
        dom!(s, "ot", "OT/ICS Security", true, 4);
    } else { dom!(s, "ot", "OT/ICS Security", false, 0); }

    // 32. Micro-Segmentation
    if config.microseg.enabled {
        use sentinel_microseg::zero_trust_engine::ZeroTrustEngine;
        use sentinel_microseg::lateral_movement_detector::LateralMovementDetector;
        use sentinel_microseg::micro_perimeter::MicroPerimeter;
        reg!(c, "microseg", "Zero Trust Engine", ZeroTrustEngine::new().with_metrics(m.clone()));
        reg!(c, "microseg", "Lateral Movement Detector", LateralMovementDetector::new().with_metrics(m.clone()));
        reg!(c, "microseg", "Micro Perimeter", MicroPerimeter::new().with_metrics(m.clone()));
        dom!(s, "microseg", "Micro-Segmentation", true, 3);
    } else { dom!(s, "microseg", "Micro-Segmentation", false, 0); }

    // 33. Backup
    if config.backup.enabled {
        use sentinel_backup::immutable_backup_validator::ImmutableBackupValidator;
        use sentinel_backup::config_drift_detector::ConfigDriftDetector;
        use sentinel_backup::encryption_auditor::EncryptionAuditor;
        use sentinel_backup::golden_image_comparator::GoldenImageComparator;
        use sentinel_backup::integrity_verifier::IntegrityVerifier;
        use sentinel_backup::retention_manager::RetentionManager;
        reg!(c, "backup", "Immutable Backup Validator", ImmutableBackupValidator::new().with_metrics(m.clone()));
        reg!(c, "backup", "Config Drift Detector", ConfigDriftDetector::new().with_metrics(m.clone()));
        reg!(c, "backup", "Encryption Auditor", EncryptionAuditor::new().with_metrics(m.clone()));
        reg!(c, "backup", "Golden Image Comparator", GoldenImageComparator::new().with_metrics(m.clone()));
        reg!(c, "backup", "Integrity Verifier", IntegrityVerifier::new().with_metrics(m.clone()));
        reg!(c, "backup", "Retention Manager", RetentionManager::new().with_metrics(m.clone()));
        dom!(s, "backup", "Backup Security", true, 6);
    } else { dom!(s, "backup", "Backup Security", false, 0); }

    // 34. Cloud
    if config.cloud.enabled {
        use sentinel_cloud::storage_exposure::StorageExposure;
        use sentinel_cloud::oauth_auditor::OauthAuditor;
        use sentinel_cloud::credential_leak_detector::CredentialLeakDetector;
        use sentinel_cloud::iam_auditor::IamAuditor;
        use sentinel_cloud::network_exposure::NetworkExposure;
        use sentinel_cloud::serverless_monitor::ServerlessMonitor;
        use sentinel_cloud::shadow_it_detector::ShadowItDetector;
        use sentinel_cloud::storage_scanner::StorageScanner;
        reg!(c, "cloud", "Storage Exposure", StorageExposure::new().with_metrics(m.clone()));
        reg!(c, "cloud", "OAuth Auditor", OauthAuditor::new().with_metrics(m.clone()));
        reg!(c, "cloud", "Credential Leak Detector", CredentialLeakDetector::new().with_metrics(m.clone()));
        reg!(c, "cloud", "IAM Auditor", IamAuditor::new(true));
        reg!(c, "cloud", "Network Exposure", NetworkExposure::new().with_metrics(m.clone()));
        reg!(c, "cloud", "Serverless Monitor", ServerlessMonitor::new().with_metrics(m.clone()));
        reg!(c, "cloud", "Shadow IT Detector", ShadowItDetector::new().with_metrics(m.clone()));
        reg!(c, "cloud", "Storage Scanner", StorageScanner::new().with_metrics(m.clone()));
        dom!(s, "cloud", "Cloud Security", true, 8);
    } else { dom!(s, "cloud", "Cloud Security", false, 0); }

    // 35. Time
    if config.time.enabled {
        use sentinel_time::ntp_integrity::NtpIntegrity;
        use sentinel_time::timestamp_validator::TimestampValidator;
        use sentinel_time::ntp_monitor::NtpMonitor;
        let drift = config.time.settings.get("max_drift_ms").and_then(|v| v.as_integer()).unwrap_or(1000);
        reg!(c, "time", "NTP Integrity", NtpIntegrity::new().with_metrics(m.clone()));
        reg!(c, "time", "Timestamp Validator", TimestampValidator::new(drift).with_metrics(m.clone()));
        reg!(c, "time", "NTP Monitor", NtpMonitor::new().with_metrics(m.clone()));
        dom!(s, "time", "Time Security", true, 3);
    } else { dom!(s, "time", "Time Security", false, 0); }

    // 36. Social Engineering
    if config.soceng.enabled {
        use sentinel_soceng::osint_monitor::OsintMonitor;
        use sentinel_soceng::deepfake_detector::DeepfakeDetector;
        use sentinel_soceng::awareness_tracker::AwarenessTracker;
        use sentinel_soceng::impersonation_detector::ImpersonationDetector;
        use sentinel_soceng::phishing_simulator::PhishingSimulator;
        use sentinel_soceng::pretexting_detector::PretextingDetector;
        reg!(c, "soceng", "OSINT Monitor", OsintMonitor::new().with_metrics(m.clone()));
        reg!(c, "soceng", "Deepfake Detector", DeepfakeDetector::new().with_metrics(m.clone()));
        reg!(c, "soceng", "Awareness Tracker", AwarenessTracker::new().with_metrics(m.clone()));
        reg!(c, "soceng", "Impersonation Detector", ImpersonationDetector::new().with_metrics(m.clone()));
        reg!(c, "soceng", "Phishing Simulator", PhishingSimulator::new().with_metrics(m.clone()));
        reg!(c, "soceng", "Pretexting Detector", PretextingDetector::new().with_metrics(m.clone()));
        dom!(s, "soceng", "Social Engineering", true, 6);
    } else { dom!(s, "soceng", "Social Engineering", false, 0); }

    // 37. Regulatory
    if config.regulatory.enabled {
        use sentinel_regulatory::gdpr_mapper::GdprMapper;
        use sentinel_regulatory::legal_hold::LegalHold;
        use sentinel_regulatory::cross_border_monitor::CrossBorderMonitor;
        use sentinel_regulatory::gdpr_monitor::GdprMonitor;
        use sentinel_regulatory::hipaa_monitor::HipaaMonitor;
        use sentinel_regulatory::pci_scanner::PciScanner;
        reg!(c, "regulatory", "GDPR Mapper", GdprMapper::new().with_metrics(m.clone()));
        reg!(c, "regulatory", "Legal Hold", LegalHold::new().with_metrics(m.clone()));
        reg!(c, "regulatory", "Cross-Border Monitor", CrossBorderMonitor::new().with_metrics(m.clone()));
        reg!(c, "regulatory", "GDPR Monitor", GdprMonitor::new().with_metrics(m.clone()));
        reg!(c, "regulatory", "HIPAA Monitor", HipaaMonitor::new().with_metrics(m.clone()));
        reg!(c, "regulatory", "PCI Scanner", PciScanner::new().with_metrics(m.clone()));
        dom!(s, "regulatory", "Regulatory", true, 6);
    } else { dom!(s, "regulatory", "Regulatory", false, 0); }

    // 38. Operations
    if config.ops.enabled {
        use sentinel_ops::service_availability::ServiceAvailability;
        use sentinel_ops::performance_baseline::PerformanceBaseline;
        use sentinel_ops::power_monitor::PowerMonitor;
        use sentinel_ops::runbook_engine::RunbookEngine;
        use sentinel_ops::sla_tracker::SlaTracker;
        use sentinel_ops::ticket_integrator::TicketIntegrator;
        reg!(c, "ops", "Service Availability", ServiceAvailability::new().with_metrics(m.clone()));
        reg!(c, "ops", "Performance Baseline", PerformanceBaseline::new().with_metrics(m.clone()));
        reg!(c, "ops", "Power Monitor", PowerMonitor::new().with_metrics(m.clone()));
        reg!(c, "ops", "Runbook Engine", RunbookEngine::new().with_metrics(m.clone()));
        reg!(c, "ops", "SLA Tracker", SlaTracker::new().with_metrics(m.clone()));
        reg!(c, "ops", "Ticket Integrator", TicketIntegrator::new().with_metrics(m.clone()));
        dom!(s, "ops", "Operations", true, 6);
    } else { dom!(s, "ops", "Operations", false, 0); }

    let enabled = s.iter().filter(|d| d.enabled).count();
    let modules: usize = s.iter().map(|d| d.module_count).sum();
    info!(domains = enabled, modules = modules, "Security stack initialized");

    SecurityStack { components: c, metrics, domain_status: Arc::new(RwLock::new(s)) }
}
