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

    // 1. Network (firewall, IDS, flow monitor initialized in main.rs)
    dom!(s, "network", "Network Security", config.network.enabled, if config.network.enabled { 3 } else { 0 });

    // 2. Endpoint
    if config.endpoint.enabled {
        use sentinel_endpoint::usb_guard::UsbGuard;
        use sentinel_endpoint::ransomware_detect::RansomwareDetector;
        reg!(c, "endpoint", "USB Guard", UsbGuard::new().with_metrics(m.clone()));
        reg!(c, "endpoint", "Ransomware Detector", RansomwareDetector::new().with_metrics(m.clone()));
        dom!(s, "endpoint", "Endpoint Protection", true, 2);
    } else { dom!(s, "endpoint", "Endpoint Protection", false, 0); }

    // 3. DNS
    if config.dns.enabled {
        use sentinel_dns::dns_filter::DnsFilter;
        use sentinel_dns::dns_sinkhole::DnsSinkhole;
        use sentinel_dns::dns_tunnel_detect::DnsTunnelDetector;
        reg!(c, "dns", "DNS Filter", DnsFilter::new().with_metrics(m.clone()));
        reg!(c, "dns", "DNS Sinkhole", DnsSinkhole::new("0.0.0.0").with_metrics(m.clone()));
        reg!(c, "dns", "DNS Tunnel Detector", DnsTunnelDetector::new().with_metrics(m.clone()));
        dom!(s, "dns", "DNS Security", true, 3);
    } else { dom!(s, "dns", "DNS Security", false, 0); }

    // 4. Email
    if config.email.enabled {
        use sentinel_email::spam_filter::SpamFilter;
        use sentinel_email::attachment_scanner::AttachmentScanner;
        use sentinel_email::dkim_validator::DkimValidator;
        reg!(c, "email", "Spam Filter", SpamFilter::new(0.7).with_metrics(m.clone()));
        reg!(c, "email", "Attachment Scanner", AttachmentScanner::new().with_metrics(m.clone()));
        reg!(c, "email", "DKIM Validator", DkimValidator::new().with_metrics(m.clone()));
        dom!(s, "email", "Email Security", true, 3);
    } else { dom!(s, "email", "Email Security", false, 0); }

    // 5. Identity
    if config.identity.enabled {
        use sentinel_identity::auth_manager::AuthManager;
        use sentinel_identity::session_manager::SessionManager;
        use sentinel_identity::mfa_engine::MfaEngine;
        use sentinel_identity::rbac_engine::RbacEngine;
        let mf = config.identity.settings.get("max_failed_attempts").and_then(|v| v.as_integer()).unwrap_or(5) as u32;
        let lo = config.identity.settings.get("lockout_duration_secs").and_then(|v| v.as_integer()).unwrap_or(900);
        let to = config.identity.settings.get("session_timeout_secs").and_then(|v| v.as_integer()).unwrap_or(3600);
        reg!(c, "identity", "Auth Manager", AuthManager::new(mf, lo).with_metrics(m.clone()));
        reg!(c, "identity", "Session Manager", SessionManager::new(100, to).with_metrics(m.clone()));
        reg!(c, "identity", "MFA Engine", MfaEngine::new().with_metrics(m.clone()));
        reg!(c, "identity", "RBAC Engine", RbacEngine::new().with_metrics(m.clone()));
        dom!(s, "identity", "Identity & Access", true, 4);
    } else { dom!(s, "identity", "Identity & Access", false, 0); }

    // 6. SIEM (correlation engine + alert manager initialized separately)
    dom!(s, "siem", "SIEM", true, 2);

    // 7. IoT
    if config.iot.enabled {
        use sentinel_iot::device_registry::DeviceRegistry;
        use sentinel_iot::anomaly_detector::AnomalyDetector;
        reg!(c, "iot", "Device Registry", DeviceRegistry::new().with_metrics(m.clone()));
        reg!(c, "iot", "Anomaly Detector", AnomalyDetector::new(0.8).with_metrics(m.clone()));
        dom!(s, "iot", "IoT Security", true, 2);
    } else { dom!(s, "iot", "IoT Security", false, 0); }

    // 8. Data
    if config.data.enabled {
        use sentinel_data::tokenizer::Tokenizer;
        use sentinel_data::dlp_scanner::DlpScanner;
        use sentinel_data::access_controller::AccessController;
        reg!(c, "data", "Tokenizer", Tokenizer::new().with_metrics(m.clone()));
        reg!(c, "data", "DLP Scanner", DlpScanner::new().with_metrics(m.clone()));
        reg!(c, "data", "Access Controller", AccessController::new().with_metrics(m.clone()));
        dom!(s, "data", "Data Protection", true, 3);
    } else { dom!(s, "data", "Data Protection", false, 0); }

    // 9. Threat Intel
    if config.threat_intel.enabled {
        use sentinel_threat_intel::stix_parser::StixParser;
        reg!(c, "threat_intel", "STIX Parser", StixParser::new().with_metrics(m.clone()));
        dom!(s, "threat_intel", "Threat Intelligence", true, 1);
    } else { dom!(s, "threat_intel", "Threat Intelligence", false, 0); }

    // 10. Forensics
    if config.forensics.enabled {
        use sentinel_forensics::evidence_collector::EvidenceCollector;
        use sentinel_forensics::timeline_builder::TimelineBuilder;
        use sentinel_forensics::artifact_extractor::ArtifactExtractor;
        use sentinel_forensics::report_writer::ReportWriter;
        reg!(c, "forensics", "Evidence Collector", EvidenceCollector::new().with_metrics(m.clone()));
        reg!(c, "forensics", "Timeline Builder", TimelineBuilder::new().with_metrics(m.clone()));
        reg!(c, "forensics", "Artifact Extractor", ArtifactExtractor::new().with_metrics(m.clone()));
        reg!(c, "forensics", "Report Writer", ReportWriter::new().with_metrics(m.clone()));
        dom!(s, "forensics", "Digital Forensics", true, 4);
    } else { dom!(s, "forensics", "Digital Forensics", false, 0); }

    // 11. Vuln
    if config.vuln.enabled {
        use sentinel_vuln::cve_database::CveDatabase;
        use sentinel_vuln::exploit_detector::ExploitDetector;
        reg!(c, "vuln", "CVE Database", CveDatabase::new().with_metrics(m.clone()));
        reg!(c, "vuln", "Exploit Detector", ExploitDetector::new().with_metrics(m.clone()));
        dom!(s, "vuln", "Vulnerability Mgmt", true, 2);
    } else { dom!(s, "vuln", "Vulnerability Mgmt", false, 0); }

    // 12. Web
    if config.web.enabled {
        use sentinel_web::waf_engine::WafEngine;
        use sentinel_web::bot_detector::BotDetector;
        use sentinel_web::content_scanner::ContentScanner;
        reg!(c, "web", "WAF Engine", WafEngine::new().with_metrics(m.clone()));
        reg!(c, "web", "Bot Detector", BotDetector::new(100).with_metrics(m.clone()));
        reg!(c, "web", "Content Scanner", ContentScanner::new().with_metrics(m.clone()));
        dom!(s, "web", "Web App Security", true, 3);
    } else { dom!(s, "web", "Web App Security", false, 0); }

    // 13. Container
    if config.container.enabled {
        use sentinel_container::image_scanner::ImageScanner;
        use sentinel_container::runtime_monitor::RuntimeMonitor;
        use sentinel_container::secret_manager::SecretManager;
        reg!(c, "container", "Image Scanner", ImageScanner::new().with_metrics(m.clone()));
        reg!(c, "container", "Runtime Monitor", RuntimeMonitor::new(0.9).with_metrics(m.clone()));
        reg!(c, "container", "Secret Manager", SecretManager::new().with_metrics(m.clone()));
        dom!(s, "container", "Container Security", true, 3);
    } else { dom!(s, "container", "Container Security", false, 0); }

    // 14. Supply Chain (no with_metrics on these)
    if config.supply_chain.enabled {
        use sentinel_supply_chain::sbom_manager::SbomManager;
        use sentinel_supply_chain::license_checker::LicenseChecker;
        reg!(c, "supply_chain", "SBOM Manager", SbomManager::new());
        reg!(c, "supply_chain", "License Checker", LicenseChecker::new());
        dom!(s, "supply_chain", "Supply Chain", true, 2);
    } else { dom!(s, "supply_chain", "Supply Chain", false, 0); }

    // 15. Compliance
    if config.compliance.enabled {
        use sentinel_compliance::policy_engine::PolicyEngine;
        use sentinel_compliance::audit_logger::AuditLogger;
        use sentinel_compliance::report_generator::ReportGenerator;
        use sentinel_compliance::control_mapper::ControlMapper;
        reg!(c, "compliance", "Policy Engine", PolicyEngine::new().with_metrics(m.clone()));
        reg!(c, "compliance", "Audit Logger", AuditLogger::new().with_metrics(m.clone()));
        reg!(c, "compliance", "Report Generator", ReportGenerator::new().with_metrics(m.clone()));
        reg!(c, "compliance", "Control Mapper", ControlMapper::new().with_metrics(m.clone()));
        dom!(s, "compliance", "Compliance", true, 4);
    } else { dom!(s, "compliance", "Compliance", false, 0); }

    // 16. Privacy (no with_metrics on these)
    if config.privacy.enabled {
        use sentinel_privacy::consent_manager::ConsentManager;
        use sentinel_privacy::retention_enforcer::RetentionEnforcer;
        use sentinel_privacy::dsar_handler::DsarHandler;
        use sentinel_privacy::pii_scanner::PiiScanner;
        reg!(c, "privacy", "Consent Manager", ConsentManager::new());
        reg!(c, "privacy", "Retention Enforcer", RetentionEnforcer::new());
        reg!(c, "privacy", "DSAR Handler", DsarHandler::new());
        reg!(c, "privacy", "PII Scanner", PiiScanner::new());
        dom!(s, "privacy", "Privacy", true, 4);
    } else { dom!(s, "privacy", "Privacy", false, 0); }

    // 17. AI Agent Security (52 modules — most comprehensive AI security layer in existence)
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
        dom!(s, "ai", "AI Agent Security", true, 52);
    } else { dom!(s, "ai", "AI Agent Security", false, 0); }

    // 18. Deception (no with_metrics on core modules)
    if config.deception.enabled {
        use sentinel_deception::dns_canary::DnsCanary;
        use sentinel_deception::honey_file::HoneyFile;
        reg!(c, "deception", "DNS Canary", DnsCanary::new().with_metrics(m.clone()));
        reg!(c, "deception", "Honey File", HoneyFile::new().with_metrics(m.clone()));
        dom!(s, "deception", "Deception Tech", true, 2);
    } else { dom!(s, "deception", "Deception Tech", false, 0); }

    // 19. Browser
    if config.browser.enabled {
        use sentinel_browser::download_scanner::DownloadScanner;
        reg!(c, "browser", "Download Scanner", DownloadScanner::new().with_metrics(m.clone()));
        dom!(s, "browser", "Browser Security", true, 1);
    } else { dom!(s, "browser", "Browser Security", false, 0); }

    // 20. API
    if config.api.enabled {
        use sentinel_api::graphql_blocker::GraphqlBlocker;
        reg!(c, "api", "GraphQL Blocker", GraphqlBlocker::new(10).with_metrics(m.clone()));
        dom!(s, "api", "API Security", true, 1);
    } else { dom!(s, "api", "API Security", false, 0); }

    // 21. VPN (no with_metrics)
    if config.vpn.enabled {
        use sentinel_vpn::tunnel_monitor::TunnelMonitor;
        use sentinel_vpn::split_tunnel::SplitTunnel;
        use sentinel_vpn::leak_detector::LeakDetector;
        reg!(c, "vpn", "Tunnel Monitor", TunnelMonitor::new());
        reg!(c, "vpn", "Split Tunnel", SplitTunnel::new());
        reg!(c, "vpn", "Leak Detector", LeakDetector::new());
        dom!(s, "vpn", "VPN Security", true, 3);
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

    // 23. Exfiltration (no with_metrics)
    if config.exfiltration.enabled {
        use sentinel_exfiltration::channel_detector::ChannelDetector;
        use sentinel_exfiltration::volume_monitor::VolumeMonitor;
        reg!(c, "exfiltration", "Channel Detector", ChannelDetector::new(0.7));
        reg!(c, "exfiltration", "Volume Monitor", VolumeMonitor::new(3.0));
        dom!(s, "exfiltration", "Data Exfiltration", true, 2);
    } else { dom!(s, "exfiltration", "Data Exfiltration", false, 0); }

    // 24. Mgmt
    if config.mgmt.enabled {
        use sentinel_mgmt::health_monitor::HealthMonitor;
        use sentinel_mgmt::alert_feed::AlertFeed;
        reg!(c, "mgmt", "Health Monitor", HealthMonitor::new().with_metrics(m.clone()));
        reg!(c, "mgmt", "Alert Feed", AlertFeed::new().with_metrics(m.clone()));
        dom!(s, "mgmt", "Management", true, 2);
    } else { dom!(s, "mgmt", "Management", false, 0); }

    // 25. Self-Protection
    if config.selfprotect.enabled {
        use sentinel_selfprotect::binary_integrity::BinaryIntegrity;
        use sentinel_selfprotect::anti_tampering::AntiTampering;
        reg!(c, "selfprotect", "Binary Integrity", BinaryIntegrity::new().with_metrics(m.clone()));
        reg!(c, "selfprotect", "Anti-Tampering", AntiTampering::new().with_metrics(m.clone()));
        dom!(s, "selfprotect", "Self-Protection", true, 2);
    } else { dom!(s, "selfprotect", "Self-Protection", false, 0); }

    // 26. Phishing
    if config.phishing.enabled {
        use sentinel_phishing::lookalike_domain::LookalikeDomainMonitor;
        use sentinel_phishing::link_scanner::LinkScanner;
        use sentinel_phishing::qr_scanner::QrScanner;
        reg!(c, "phishing", "Lookalike Domain", LookalikeDomainMonitor::new().with_metrics(m.clone()));
        reg!(c, "phishing", "Link Scanner", LinkScanner::new().with_metrics(m.clone()));
        reg!(c, "phishing", "QR Scanner", QrScanner::new().with_metrics(m.clone()));
        dom!(s, "phishing", "Anti-Phishing", true, 3);
    } else { dom!(s, "phishing", "Anti-Phishing", false, 0); }

    // 27. Crypto
    if config.crypto.enabled {
        use sentinel_crypto::tls_auditor::TlsAuditor;
        use sentinel_crypto::ca_monitor::CaMonitor;
        use sentinel_crypto::key_rotation::KeyRotation;
        reg!(c, "crypto", "TLS Auditor", TlsAuditor::new().with_metrics(m.clone()));
        reg!(c, "crypto", "CA Monitor", CaMonitor::new().with_metrics(m.clone()));
        reg!(c, "crypto", "Key Rotation", KeyRotation::new().with_metrics(m.clone()));
        dom!(s, "crypto", "Cryptography", true, 3);
    } else { dom!(s, "crypto", "Cryptography", false, 0); }

    // 28. Resilience
    if config.resilience.enabled {
        use sentinel_resilience::auto_quarantine::AutoQuarantine;
        use sentinel_resilience::kill_switch::KillSwitch;
        reg!(c, "resilience", "Auto-Quarantine", AutoQuarantine::new().with_metrics(m.clone()));
        reg!(c, "resilience", "Kill Switch", KillSwitch::new().with_metrics(m.clone()));
        dom!(s, "resilience", "Resilience", true, 2);
    } else { dom!(s, "resilience", "Resilience", false, 0); }

    // 29. Mobile
    if config.mobile.enabled {
        use sentinel_mobile::app_permission_auditor::AppPermissionAuditor;
        use sentinel_mobile::network_traffic_monitor::NetworkTrafficMonitor;
        reg!(c, "mobile", "App Permission Auditor", AppPermissionAuditor::new().with_metrics(m.clone()));
        reg!(c, "mobile", "Network Traffic Monitor", NetworkTrafficMonitor::new().with_metrics(m.clone()));
        dom!(s, "mobile", "Mobile Security", true, 2);
    } else { dom!(s, "mobile", "Mobile Security", false, 0); }

    // 30. Dark Web
    if config.darkweb.enabled {
        use sentinel_darkweb::domain_reputation::DomainReputationMonitor;
        use sentinel_darkweb::exposed_service_detector::ExposedServiceDetector;
        use sentinel_darkweb::breach_credential_monitor::BreachCredentialMonitor;
        reg!(c, "darkweb", "Domain Reputation", DomainReputationMonitor::new().with_metrics(m.clone()));
        reg!(c, "darkweb", "Exposed Service Detector", ExposedServiceDetector::new().with_metrics(m.clone()));
        reg!(c, "darkweb", "Breach Credential Monitor", BreachCredentialMonitor::new().with_metrics(m.clone()));
        dom!(s, "darkweb", "Dark Web Intel", true, 3);
    } else { dom!(s, "darkweb", "Dark Web Intel", false, 0); }

    // 31. OT/ICS
    if config.ot.enabled {
        use sentinel_ot::scada_monitor::ScadaMonitor;
        use sentinel_ot::serial_monitor::SerialMonitor;
        use sentinel_ot::plc_integrity::PlcIntegrity;
        reg!(c, "ot", "SCADA Monitor", ScadaMonitor::new().with_metrics(m.clone()));
        reg!(c, "ot", "Serial Monitor", SerialMonitor::new().with_metrics(m.clone()));
        reg!(c, "ot", "PLC Integrity", PlcIntegrity::new().with_metrics(m.clone()));
        dom!(s, "ot", "OT/ICS Security", true, 3);
    } else { dom!(s, "ot", "OT/ICS Security", false, 0); }

    // 32. Micro-Segmentation
    if config.microseg.enabled {
        use sentinel_microseg::zero_trust_engine::ZeroTrustEngine;
        use sentinel_microseg::lateral_movement_detector::LateralMovementDetector;
        reg!(c, "microseg", "Zero Trust Engine", ZeroTrustEngine::new().with_metrics(m.clone()));
        reg!(c, "microseg", "Lateral Movement Detector", LateralMovementDetector::new().with_metrics(m.clone()));
        dom!(s, "microseg", "Micro-Segmentation", true, 2);
    } else { dom!(s, "microseg", "Micro-Segmentation", false, 0); }

    // 33. Backup
    if config.backup.enabled {
        use sentinel_backup::immutable_backup_validator::ImmutableBackupValidator;
        use sentinel_backup::config_drift_detector::ConfigDriftDetector;
        reg!(c, "backup", "Immutable Backup Validator", ImmutableBackupValidator::new().with_metrics(m.clone()));
        reg!(c, "backup", "Config Drift Detector", ConfigDriftDetector::new().with_metrics(m.clone()));
        dom!(s, "backup", "Backup Security", true, 2);
    } else { dom!(s, "backup", "Backup Security", false, 0); }

    // 34. Cloud
    if config.cloud.enabled {
        use sentinel_cloud::storage_exposure::StorageExposure;
        use sentinel_cloud::oauth_auditor::OauthAuditor;
        reg!(c, "cloud", "Storage Exposure", StorageExposure::new().with_metrics(m.clone()));
        reg!(c, "cloud", "OAuth Auditor", OauthAuditor::new().with_metrics(m.clone()));
        dom!(s, "cloud", "Cloud Security", true, 2);
    } else { dom!(s, "cloud", "Cloud Security", false, 0); }

    // 35. Time
    if config.time.enabled {
        use sentinel_time::ntp_integrity::NtpIntegrity;
        use sentinel_time::timestamp_validator::TimestampValidator;
        let drift = config.time.settings.get("max_drift_ms").and_then(|v| v.as_integer()).unwrap_or(1000);
        reg!(c, "time", "NTP Integrity", NtpIntegrity::new().with_metrics(m.clone()));
        reg!(c, "time", "Timestamp Validator", TimestampValidator::new(drift).with_metrics(m.clone()));
        dom!(s, "time", "Time Security", true, 2);
    } else { dom!(s, "time", "Time Security", false, 0); }

    // 36. Social Engineering
    if config.soceng.enabled {
        use sentinel_soceng::osint_monitor::OsintMonitor;
        use sentinel_soceng::deepfake_detector::DeepfakeDetector;
        reg!(c, "soceng", "OSINT Monitor", OsintMonitor::new().with_metrics(m.clone()));
        reg!(c, "soceng", "Deepfake Detector", DeepfakeDetector::new().with_metrics(m.clone()));
        dom!(s, "soceng", "Social Engineering", true, 2);
    } else { dom!(s, "soceng", "Social Engineering", false, 0); }

    // 37. Regulatory
    if config.regulatory.enabled {
        use sentinel_regulatory::gdpr_mapper::GdprMapper;
        use sentinel_regulatory::legal_hold::LegalHold;
        reg!(c, "regulatory", "GDPR Mapper", GdprMapper::new().with_metrics(m.clone()));
        reg!(c, "regulatory", "Legal Hold", LegalHold::new().with_metrics(m.clone()));
        dom!(s, "regulatory", "Regulatory", true, 2);
    } else { dom!(s, "regulatory", "Regulatory", false, 0); }

    // 38. Operations
    if config.ops.enabled {
        use sentinel_ops::service_availability::ServiceAvailability;
        use sentinel_ops::performance_baseline::PerformanceBaseline;
        reg!(c, "ops", "Service Availability", ServiceAvailability::new().with_metrics(m.clone()));
        reg!(c, "ops", "Performance Baseline", PerformanceBaseline::new().with_metrics(m.clone()));
        dom!(s, "ops", "Operations", true, 2);
    } else { dom!(s, "ops", "Operations", false, 0); }

    let enabled = s.iter().filter(|d| d.enabled).count();
    let modules: usize = s.iter().map(|d| d.module_count).sum();
    info!(domains = enabled, modules = modules, "Security stack initialized");

    SecurityStack { components: c, metrics, domain_status: Arc::new(RwLock::new(s)) }
}
