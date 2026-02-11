//! End-to-end integration tests for Nexus Sentinel
//!
//! These tests exercise real multi-component scenarios:
//! - Detection → Correlation → Response pipeline flows
//! - Event bus routing across crate boundaries
//! - Config loading and validation
//! - Persistence snapshot/restore cycles
//! - WAF + Link Scanner + TLS Auditor real detection logic

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use sentinel_core::config_loader::SentinelConfig;
use sentinel_core::event_bus::*;
use sentinel_core::persistence::PersistenceManager;
use sentinel_core::pipeline::*;
use sentinel_core::MemoryMetrics;

// ── Scenario 1: Full Detection → Correlation → Response Pipeline ─────────

#[test]
fn test_detection_to_response_pipeline() {
    let bus = EventBus::new();
    let engine = Arc::new(PipelineEngine::new());

    engine.register(PipelineDefinition {
        name: "malware_containment".into(),
        description: "Detect malware → correlate → quarantine".into(),
        trigger_category: EventCategory::Detection,
        trigger_severity_min: EventSeverity::High,
        trigger_tags: vec!["malware".into()],
        stages: vec![
            PipelineStage {
                name: "correlate".into(),
                component: "correlator".into(),
                output_category: EventCategory::Correlation,
                handler: Arc::new(|event, _bus| {
                    let mut details = event.details.clone();
                    details.insert("correlated".into(), "true".into());
                    Some(SecurityEvent {
                        id: 0,
                        timestamp_ms: 0,
                        source_component: "correlator".into(),
                        source_crate: "sentinel-siem".into(),
                        category: EventCategory::Correlation,
                        severity: event.severity,
                        title: format!("Correlated: {}", event.title),
                        details,
                        caused_by: vec![event.id],
                        tags: event.tags.clone(),
                    })
                }),
            },
            PipelineStage {
                name: "quarantine".into(),
                component: "auto_quarantine".into(),
                output_category: EventCategory::Response,
                handler: Arc::new(|event, _bus| {
                    let mut details = event.details.clone();
                    details.insert("quarantined".into(), "device-001".into());
                    Some(SecurityEvent {
                        id: 0,
                        timestamp_ms: 0,
                        source_component: "auto_quarantine".into(),
                        source_crate: "sentinel-resilience".into(),
                        category: EventCategory::Response,
                        severity: event.severity,
                        title: "Device quarantined".into(),
                        details,
                        caused_by: vec![event.id],
                        tags: vec!["quarantine".into()],
                    })
                }),
            },
        ],
        enabled: true,
    });

    let trigger = SecurityEvent {
        id: 1,
        timestamp_ms: chrono::Utc::now().timestamp_millis(),
        source_component: "endpoint_scanner".into(),
        source_crate: "sentinel-endpoint".into(),
        category: EventCategory::Detection,
        severity: EventSeverity::Critical,
        title: "Malware detected on device-001".into(),
        details: {
            let mut d = HashMap::new();
            d.insert("device".into(), "device-001".into());
            d.insert("hash".into(), "abc123".into());
            d
        },
        caused_by: vec![],
        tags: vec!["malware".into(), "endpoint".into()],
    };

    let final_id = engine.execute_with_bus("malware_containment", &trigger, &bus);
    assert!(final_id.is_some());

    assert_eq!(engine.total_runs(), 1);
    assert_eq!(engine.total_completed(), 1);
    assert_eq!(engine.total_failed(), 0);

    let runs = engine.recent_runs(10);
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].stages_completed, 2);
    assert_eq!(runs[0].status, RunStatus::Completed);
    assert_eq!(runs[0].event_chain.len(), 3);

    let responses = bus.recent_events(10, Some(EventCategory::Response));
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].title, "Device quarantined");
    assert!(responses[0].details.contains_key("quarantined"));
}

// ── Scenario 2: Event Bus Cross-Crate Routing ────────────────────────────

#[test]
fn test_cross_crate_event_routing() {
    let bus = EventBus::new();

    let network_count = Arc::new(AtomicU64::new(0));
    let endpoint_count = Arc::new(AtomicU64::new(0));
    let all_count = Arc::new(AtomicU64::new(0));

    let nc = network_count.clone();
    bus.subscribe("network_sub", None, None, vec!["network".into()],
        Arc::new(move |_| { nc.fetch_add(1, Ordering::Relaxed); }));

    let ec = endpoint_count.clone();
    bus.subscribe("endpoint_sub", None, None, vec!["endpoint".into()],
        Arc::new(move |_| { ec.fetch_add(1, Ordering::Relaxed); }));

    let ac = all_count.clone();
    bus.subscribe("all_high", None, Some(EventSeverity::High), vec![],
        Arc::new(move |_| { ac.fetch_add(1, Ordering::Relaxed); }));

    bus.emit_detection("firewall", "sentinel-network", EventSeverity::High,
        "Port scan detected", HashMap::new(), vec!["network".into()]);

    bus.emit_detection("process_monitor", "sentinel-endpoint", EventSeverity::Critical,
        "Suspicious process", HashMap::new(), vec!["endpoint".into()]);

    bus.emit_detection("dns_tunnel", "sentinel-dns", EventSeverity::Medium,
        "Possible tunnel", HashMap::new(), vec!["dns".into()]);

    assert_eq!(network_count.load(Ordering::Relaxed), 1);
    assert_eq!(endpoint_count.load(Ordering::Relaxed), 1);
    assert_eq!(all_count.load(Ordering::Relaxed), 2);
    assert_eq!(bus.total_published(), 3);
}

// ── Scenario 3: Pipeline Abort on Stage Failure ──────────────────────────

#[test]
fn test_pipeline_abort_on_failure() {
    let bus = EventBus::new();
    let engine = Arc::new(PipelineEngine::new());

    engine.register(PipelineDefinition {
        name: "failing_pipeline".into(),
        description: "Second stage fails".into(),
        trigger_category: EventCategory::Detection,
        trigger_severity_min: EventSeverity::Low,
        trigger_tags: vec![],
        stages: vec![
            PipelineStage {
                name: "stage_1".into(), component: "comp1".into(),
                output_category: EventCategory::Correlation,
                handler: Arc::new(|event, _| Some(SecurityEvent {
                    id: 0, timestamp_ms: 0,
                    source_component: "comp1".into(), source_crate: "test".into(),
                    category: EventCategory::Correlation, severity: event.severity,
                    title: "Stage 1 OK".into(), details: HashMap::new(),
                    caused_by: vec![event.id], tags: vec![],
                })),
            },
            PipelineStage {
                name: "stage_2_fails".into(), component: "comp2".into(),
                output_category: EventCategory::Response,
                handler: Arc::new(|_event, _| None),
            },
            PipelineStage {
                name: "stage_3_never".into(), component: "comp3".into(),
                output_category: EventCategory::Notification,
                handler: Arc::new(|event, _| Some(event.clone())),
            },
        ],
        enabled: true,
    });

    let trigger = SecurityEvent {
        id: 1, timestamp_ms: 0,
        source_component: "test".into(), source_crate: "test".into(),
        category: EventCategory::Detection, severity: EventSeverity::High,
        title: "test".into(), details: HashMap::new(),
        caused_by: vec![], tags: vec![],
    };

    engine.execute_with_bus("failing_pipeline", &trigger, &bus);

    assert_eq!(engine.total_runs(), 1);
    assert_eq!(engine.total_failed(), 1);
    assert_eq!(engine.total_completed(), 0);

    let runs = engine.recent_runs(10);
    assert_eq!(runs[0].status, RunStatus::Aborted);
    assert_eq!(runs[0].stages_completed, 1);
    assert!(runs[0].error.as_ref().unwrap().contains("stage_2_fails"));
}

// ── Scenario 4: Config Load + Validation ─────────────────────────────────

#[test]
fn test_config_load_defaults() {
    let config = SentinelConfig::default();
    assert_eq!(config.general.memory_budget_mb, 512);
    assert!(config.general.event_bus_enabled);
    assert_eq!(config.enabled_layer_count(), 37);
}

#[test]
fn test_config_roundtrip() {
    let dir = std::env::temp_dir().join("sentinel_config_rt_test");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let path = dir.join("test_sentinel.toml");
    let config = SentinelConfig::default();
    config.save(&path).unwrap();

    let loaded = SentinelConfig::load(&path).unwrap();
    assert_eq!(loaded.general.memory_budget_mb, config.general.memory_budget_mb);
    assert_eq!(loaded.general.log_level, config.general.log_level);
    assert_eq!(loaded.enabled_layer_count(), config.enabled_layer_count());

    let _ = std::fs::remove_dir_all(&dir);
}

// ── Scenario 5: Persistence Snapshot + Restore ───────────────────────────

#[test]
fn test_persistence_snapshot_restore_cycle() {
    use sentinel_core::persistence::Persistable;

    struct CounterComponent {
        name: String,
        value: parking_lot::RwLock<u64>,
    }

    impl Persistable for CounterComponent {
        fn persist_name(&self) -> &str { &self.name }
        fn snapshot(&self) -> Result<Vec<u8>, String> {
            serde_json::to_vec(&*self.value.read()).map_err(|e| e.to_string())
        }
        fn restore(&self, data: &[u8]) -> Result<(), String> {
            let val: u64 = serde_json::from_slice(data).map_err(|e| e.to_string())?;
            *self.value.write() = val;
            Ok(())
        }
    }

    let dir = std::env::temp_dir().join("sentinel_persist_integ_test");
    let _ = std::fs::remove_dir_all(&dir);

    let mgr = PersistenceManager::new(&dir);
    mgr.init().unwrap();

    let comp_a = Arc::new(CounterComponent { name: "comp_a".into(), value: parking_lot::RwLock::new(42) });
    let comp_b = Arc::new(CounterComponent { name: "comp_b".into(), value: parking_lot::RwLock::new(100) });
    mgr.register(comp_a.clone());
    mgr.register(comp_b.clone());

    let results = mgr.snapshot_all();
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|r| r.is_ok()));

    *comp_a.value.write() = 0;
    *comp_b.value.write() = 0;

    let restore_results = mgr.restore_all();
    assert!(restore_results.iter().all(|(_, r)| r.is_ok()));

    assert_eq!(*comp_a.value.read(), 42);
    assert_eq!(*comp_b.value.read(), 100);

    let _ = std::fs::remove_dir_all(&dir);
}

// ── Scenario 6: WAF Real Attack Detection ────────────────────────────────

#[test]
fn test_waf_detects_sql_injection() {
    let waf = sentinel_web::waf_engine::WafEngine::new();
    waf.load_builtin_rules();

    assert!(waf.inspect("/api/users?page=1", ""));
    assert!(!waf.inspect("/api/users?id=' or 1=1--", ""));
    assert!(!waf.inspect("/api/search", "query=1; drop table users"));
    assert!(!waf.inspect("/comment", "body=<script>alert(1)</script>"));
    assert!(!waf.inspect("/files/../../../etc/passwd", ""));

    assert!(waf.total_blocked() >= 4);
}

#[test]
fn test_waf_url_encoded_evasion() {
    let waf = sentinel_web::waf_engine::WafEngine::new();
    waf.load_builtin_rules();

    let (allowed, rule) = waf.inspect_full("/page", "%3Cscript%3Ealert(1)%3C/script%3E", &[]);
    assert!(!allowed);
    assert!(rule.unwrap().starts_with("xss"));
}

// ── Scenario 7: Link Scanner URL Heuristics ──────────────────────────────

#[test]
fn test_link_scanner_heuristics() {
    let scanner = sentinel_phishing::link_scanner::LinkScanner::new();

    let result = scanner.scan_url("https://google.com/search?q=rust");
    assert_eq!(result.verdict, sentinel_phishing::link_scanner::LinkVerdict::Safe);

    let result = scanner.scan_url("http://192.168.1.1/login/verify/account");
    assert!(result.verdict == sentinel_phishing::link_scanner::LinkVerdict::Malicious
        || result.verdict == sentinel_phishing::link_scanner::LinkVerdict::Suspicious);

    let result = scanner.scan_url("data:text/html,<h1>phish</h1>");
    assert_ne!(result.verdict, sentinel_phishing::link_scanner::LinkVerdict::Safe);
}

// ── Scenario 8: TLS Auditor Compliance Checks ────────────────────────────

#[test]
fn test_tls_auditor_compliance() {
    let auditor = sentinel_crypto::tls_auditor::TlsAuditor::new();

    let result = auditor.audit_connection("good.example.com", 443, "TLSv1.3", "TLS_AES_256_GCM_SHA384");
    assert!(result.compliant);
    assert!(result.findings.is_empty());

    let result = auditor.audit_connection("old.example.com", 443, "TLSv1.0", "AES128-SHA");
    assert!(!result.compliant);
    assert!(result.findings.iter().any(|f| f.contains("deprecated")));

    let result = auditor.audit_connection("weak.example.com", 443, "TLSv1.2", "RC4-SHA");
    assert!(!result.compliant);
    assert!(result.findings.iter().any(|f| f.contains("RC4")));

    assert_eq!(auditor.total_audited(), 3);
    assert_eq!(auditor.non_compliant(), 2);
}

// ── Scenario 9: Lookalike Domain Detection ───────────────────────────────

#[test]
fn test_lookalike_domain_detection() {
    let monitor = sentinel_phishing::lookalike_domain::LookalikeDomainMonitor::new();
    monitor.add_monitored("google.com");
    monitor.add_monitored("microsoft.com");

    let result = monitor.check_domain("google.com");
    assert!(result.is_none());

    let result = monitor.check_domain("googel.com");
    assert!(result.is_some());

    let result = monitor.check_domain("amazon.com");
    assert!(result.is_none());
}

// ── Scenario 10: Memory Metrics Budget Enforcement ───────────────────────

#[test]
fn test_memory_budget_tracking() {
    let metrics = MemoryMetrics::new(64 * 1024 * 1024);

    metrics.register_component("firewall", 8 * 1024 * 1024);
    metrics.register_component("ids", 16 * 1024 * 1024);
    metrics.register_component("dns", 4 * 1024 * 1024);

    let report = metrics.report();
    assert_eq!(report.total_budget, 64 * 1024 * 1024);
    assert_eq!(report.components.len(), 3);
}

// ── Scenario 11: Event Correlation Chain Tracing ─────────────────────────

#[test]
fn test_full_correlation_chain() {
    let bus = EventBus::new();

    let det_id = bus.emit_detection(
        "ids", "sentinel-network", EventSeverity::High,
        "Signature match: lateral movement",
        HashMap::new(), vec!["lateral-movement".into()],
    );

    let cor_id = bus.emit_correlation(
        "correlator", "sentinel-siem", EventSeverity::High,
        "Lateral movement confirmed across 3 hosts",
        {
            let mut d = HashMap::new();
            d.insert("hosts".into(), "srv1,srv2,srv3".into());
            d
        },
        vec![det_id],
        vec!["lateral-movement".into()],
    );

    let _resp_id = bus.emit_response(
        "auto_quarantine", "sentinel-resilience", EventSeverity::High,
        "Quarantined 3 hosts",
        HashMap::new(),
        vec![cor_id],
        vec!["quarantine".into()],
    );

    let chain1 = bus.trace_event(det_id);
    assert_eq!(chain1.len(), 1);
    assert!(chain1[0].title.contains("confirmed"));

    let chain2 = bus.trace_event(cor_id);
    assert_eq!(chain2.len(), 1);
    assert!(chain2[0].title.contains("Quarantined"));

    let lateral = bus.events_by_tag("lateral-movement", 10);
    assert_eq!(lateral.len(), 2);

    let quarantine = bus.events_by_tag("quarantine", 10);
    assert_eq!(quarantine.len(), 1);
}
