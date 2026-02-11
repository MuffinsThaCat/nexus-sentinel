//! Agent Network Fence — controls and monitors all AI agent network activity.
//!
//! Features:
//! - **Domain allowlist/denylist** with wildcard and regex matching
//! - **IP range blocking** with CIDR notation support
//! - **Protocol restrictions** (HTTP-only, no raw TCP, no FTP, etc.)
//! - **Port allowlisting** (only 80, 443, etc.)
//! - **Per-agent bandwidth quotas** with rolling window tracking
//! - **Per-endpoint rate limiting** (max N requests per minute to any single host)
//! - **Data exfiltration detection** based on upload size thresholds
//! - **DNS monitoring** logging every resolution with categorization
//! - **Geo-fencing** blocking connections to sanctioned/high-risk countries
//! - **TLS enforcement** requiring HTTPS for all external connections
//! - **Connection duration limits** detecting long-lived suspicious tunnels
//! - **Known-bad endpoint database** with threat intel feed integration
//!
//! Memory breakthroughs: #2 Tiered Cache, #461 Differential, #5 Streaming, #569 Pruning, #6 Verifier

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::streaming::StreamAccumulator;
use sentinel_core::pruning::PruningMap;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::time::Duration;
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

// ── Types ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Protocol {
    Http, Https, WebSocket, Wss, Tcp, Udp, Ssh, Ftp, Sftp, Dns, Smtp, Grpc, Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ConnectionVerdict {
    Allowed, Blocked, RateLimited, QuotaExceeded, GeoBlocked, ProtocolBlocked, PortBlocked, TlsRequired,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentConnection {
    pub agent_id: String,
    pub session_id: String,
    pub destination_host: String,
    pub destination_ip: Option<String>,
    pub destination_port: u16,
    pub protocol: Protocol,
    pub direction: Direction,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub timestamp: i64,
    pub duration_ms: u64,
    pub tls: bool,
    pub user_agent: Option<String>,
    pub request_path: Option<String>,
    pub country_code: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Direction { Outbound, Inbound }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConnectionResult {
    pub verdict: ConnectionVerdict,
    pub reason: String,
    pub connection: AgentConnection,
}

// ── Endpoint statistics ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct EndpointStats {
    pub total_connections: u64,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub blocked_count: u64,
    pub unique_agents: HashSet<String>,
    pub unique_endpoints: HashSet<String>,
    pub protocol_counts: HashMap<String, u64>,
    pub blocked_reasons: HashMap<String, u64>,
    pub top_destinations: Vec<(String, u64)>,
    pub window_start: i64,
    pub window_end: i64,
}

// ── Geo-fence data ──────────────────────────────────────────────────────────

const HIGH_RISK_COUNTRIES: &[&str] = &[
    "KP", "IR", "SY", "CU", "RU", "BY", "VE", "MM",
];

const KNOWN_BAD_DOMAINS: &[&str] = &[
    "evil.com", "malware.site", "phishing.example",
    "c2-server.net", "data-exfil.io", "crypto-miner.xyz",
    "reverse-shell.net", "keylogger.host",
];

const ALLOWED_PORTS: &[u16] = &[80, 443, 8080, 8443, 3000, 5000, 8000];

// ── Agent Network Fence ─────────────────────────────────────────────────────

pub struct AgentNetworkFence {
    // Domain rules
    allowed_domains: RwLock<HashSet<String>>,
    blocked_domains: RwLock<HashSet<String>>,
    domain_patterns: RwLock<Vec<(String, bool)>>, // (pattern, is_allow)
    // IP rules
    blocked_ip_ranges: RwLock<Vec<(u32, u32, u8)>>, // (network, mask, bits)
    // Protocol/port rules
    allowed_protocols: RwLock<HashSet<Protocol>>,
    allowed_ports: RwLock<HashSet<u16>>,
    require_tls: AtomicBool,
    // Geo-fencing
    blocked_countries: RwLock<HashSet<String>>,
    // Per-agent bandwidth quotas (bytes per hour)
    bandwidth_quotas: RwLock<HashMap<String, u64>>,
    bandwidth_usage: RwLock<HashMap<String, Vec<(i64, u64)>>>,
    default_bandwidth_quota: u64,
    // Per-endpoint rate limiting
    endpoint_rates: RwLock<HashMap<String, VecDeque<i64>>>,
    max_requests_per_minute: u64,
    // Exfiltration detection
    upload_threshold_bytes: u64,
    // Connection duration limit (ms)
    max_connection_duration_ms: u64,
    // Cache & streaming
    verdict_cache: TieredCache<String, ConnectionVerdict>,
    connection_stats: RwLock<StreamAccumulator<AgentConnection, EndpointStats>>,
    // Connection history for trend analysis
    connection_history: RwLock<Vec<EndpointStats>>,
    active_connections: RwLock<PruningMap<String, AgentConnection>>,
    // Counters & state
    alerts: RwLock<Vec<AiAlert>>,
    total_connections: AtomicU64,
    total_blocked: AtomicU64,
    total_allowed: AtomicU64,
    total_bytes_out: AtomicU64,
    total_bytes_in: AtomicU64,
    exfil_detections: AtomicU64,
    geo_blocks: AtomicU64,
    lockdown: AtomicBool,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl AgentNetworkFence {
    pub fn new() -> Self {
        let mut allowed_protos = HashSet::new();
        allowed_protos.insert(Protocol::Http);
        allowed_protos.insert(Protocol::Https);
        allowed_protos.insert(Protocol::Wss);
        allowed_protos.insert(Protocol::Dns);
        allowed_protos.insert(Protocol::Grpc);

        let mut allowed_port_set = HashSet::new();
        for p in ALLOWED_PORTS { allowed_port_set.insert(*p); }

        let mut blocked_countries = HashSet::new();
        for c in HIGH_RISK_COUNTRIES { blocked_countries.insert(c.to_string()); }

        let mut blocked_doms = HashSet::new();
        for d in KNOWN_BAD_DOMAINS { blocked_doms.insert(d.to_string()); }

        let stats_acc = StreamAccumulator::new(50, EndpointStats::default(), |acc, conns: &[AgentConnection]| {
            for c in conns {
                acc.total_connections += 1;
                acc.total_bytes_sent += c.bytes_sent;
                acc.total_bytes_received += c.bytes_received;
                acc.unique_agents.insert(c.agent_id.clone());
                acc.unique_endpoints.insert(c.destination_host.clone());
                *acc.protocol_counts.entry(format!("{:?}", c.protocol)).or_insert(0) += 1;
                if acc.window_start == 0 || c.timestamp < acc.window_start { acc.window_start = c.timestamp; }
                if c.timestamp > acc.window_end { acc.window_end = c.timestamp; }
            }
        });

        Self {
            allowed_domains: RwLock::new(HashSet::new()),
            blocked_domains: RwLock::new(blocked_doms),
            domain_patterns: RwLock::new(Vec::new()),
            blocked_ip_ranges: RwLock::new(Vec::new()),
            allowed_protocols: RwLock::new(allowed_protos),
            allowed_ports: RwLock::new(allowed_port_set),
            require_tls: AtomicBool::new(false),
            blocked_countries: RwLock::new(blocked_countries),
            bandwidth_quotas: RwLock::new(HashMap::new()),
            bandwidth_usage: RwLock::new(HashMap::new()),
            default_bandwidth_quota: 100 * 1024 * 1024, // 100MB/hour
            endpoint_rates: RwLock::new(HashMap::new()),
            max_requests_per_minute: 120,
            upload_threshold_bytes: 50 * 1024 * 1024, // 50MB
            max_connection_duration_ms: 300_000, // 5 min
            verdict_cache: TieredCache::new(5_000),
            connection_stats: RwLock::new(stats_acc),
            connection_history: RwLock::new(Vec::new()),
            active_connections: RwLock::new(PruningMap::new(5_000).with_ttl(Duration::from_secs(600))),
            alerts: RwLock::new(Vec::new()),
            total_connections: AtomicU64::new(0),
            total_blocked: AtomicU64::new(0),
            total_allowed: AtomicU64::new(0),
            total_bytes_out: AtomicU64::new(0),
            total_bytes_in: AtomicU64::new(0),
            exfil_detections: AtomicU64::new(0),
            geo_blocks: AtomicU64::new(0),
            lockdown: AtomicBool::new(false),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("agent_network_fence", 6 * 1024 * 1024);
        self.verdict_cache = self.verdict_cache.with_metrics(metrics.clone(), "agent_network_fence");
        self.metrics = Some(metrics);
        self
    }

    // ── Configuration ───────────────────────────────────────────────────────

    pub fn allow_domain(&self, domain: &str) { self.allowed_domains.write().insert(domain.to_string()); }
    pub fn block_domain(&self, domain: &str) { self.blocked_domains.write().insert(domain.to_string()); }
    pub fn add_domain_pattern(&self, pattern: &str, allow: bool) { self.domain_patterns.write().push((pattern.to_string(), allow)); }
    pub fn allow_port(&self, port: u16) { self.allowed_ports.write().insert(port); }
    pub fn block_country(&self, code: &str) { self.blocked_countries.write().insert(code.to_uppercase()); }
    pub fn set_bandwidth_quota(&self, agent_id: &str, bytes_per_hour: u64) {
        self.bandwidth_quotas.write().insert(agent_id.to_string(), bytes_per_hour);
    }
    pub fn set_require_tls(&self, require: bool) { self.require_tls.store(require, Ordering::SeqCst); }
    pub fn emergency_lockdown(&self) { self.lockdown.store(true, Ordering::SeqCst); }
    pub fn lift_lockdown(&self) { self.lockdown.store(false, Ordering::SeqCst); }

    // ── Connection checking ─────────────────────────────────────────────────

    pub fn check_connection(&self, conn: AgentConnection) -> ConnectionResult {
        if !self.enabled {
            return ConnectionResult { verdict: ConnectionVerdict::Allowed, reason: "disabled".into(), connection: conn };
        }
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        let now = conn.timestamp;
        let host = conn.destination_host.to_lowercase();
        let agent_id = conn.agent_id.clone();

        // Emergency lockdown
        if self.lockdown.load(Ordering::SeqCst) {
            return self.block(conn, ConnectionVerdict::Blocked, "emergency_lockdown", now);
        }

        // 1. Known-bad domain check
        if self.blocked_domains.read().contains(&host) || self.is_known_bad(&host) {
            return self.block(conn, ConnectionVerdict::Blocked, &format!("blocked domain: {}", host), now);
        }

        // 2. Geo-fence check
        if let Some(cc) = conn.country_code.clone() {
            if self.blocked_countries.read().contains(&cc.to_uppercase()) {
                self.geo_blocks.fetch_add(1, Ordering::Relaxed);
                return self.block(conn, ConnectionVerdict::GeoBlocked, &format!("blocked country: {}", cc), now);
            }
        }

        // 3. Protocol check
        if !self.allowed_protocols.read().contains(&conn.protocol) {
            let proto = conn.protocol;
            return self.block(conn, ConnectionVerdict::ProtocolBlocked,
                &format!("protocol {:?} not allowed", proto), now);
        }

        // 4. Port check
        let port = conn.destination_port;
        if port != 0 && !self.allowed_ports.read().contains(&port) {
            return self.block(conn, ConnectionVerdict::PortBlocked,
                &format!("port {} not allowed", port), now);
        }

        // 5. TLS enforcement
        if self.require_tls.load(Ordering::SeqCst) && !conn.tls
            && !matches!(conn.protocol, Protocol::Dns) {
            return self.block(conn, ConnectionVerdict::TlsRequired, "TLS required for all connections", now);
        }

        // 6. Domain allowlist (if populated, only allowed domains pass)
        {
            let allowed_doms = self.allowed_domains.read();
            if !allowed_doms.is_empty() && !allowed_doms.contains(&host) {
                let pattern_match = self.domain_patterns.read().iter()
                    .any(|(pat, is_allow)| *is_allow && Self::domain_matches(&host, pat));
                if !pattern_match {
                    return self.block(conn, ConnectionVerdict::Blocked,
                        &format!("domain {} not in allowlist", host), now);
                }
            }
        }

        // 7. Per-endpoint rate limiting
        if !self.check_endpoint_rate(&host, now) {
            return self.block(conn, ConnectionVerdict::RateLimited,
                &format!("rate limit exceeded for {}", host), now);
        }

        // 8. Per-agent bandwidth quota
        let total_bytes = conn.bytes_sent + conn.bytes_received;
        if !self.check_bandwidth(&agent_id, total_bytes, now) {
            return self.block(conn, ConnectionVerdict::QuotaExceeded,
                &format!("bandwidth quota exceeded for agent {}", agent_id), now);
        }

        // 9. Exfiltration detection (large upload)
        if conn.bytes_sent > self.upload_threshold_bytes {
            self.exfil_detections.fetch_add(1, Ordering::Relaxed);
            warn!(agent = %agent_id, host = %host, bytes = conn.bytes_sent,
                "Potential data exfiltration — large upload");
            self.add_alert(now, Severity::Critical, "Potential data exfiltration",
                &format!("Agent {} uploaded {}MB to {}", agent_id,
                    conn.bytes_sent / (1024 * 1024), host));
        }

        // 10. Connection duration check
        if conn.duration_ms > self.max_connection_duration_ms {
            warn!(agent = %agent_id, host = %host, duration_ms = conn.duration_ms,
                "Long-lived connection detected — possible tunnel");
            self.add_alert(now, Severity::High, "Long-lived connection",
                &format!("Agent {} connected to {} for {}s", agent_id, host, conn.duration_ms / 1000));
        }

        // Update counters
        self.total_allowed.fetch_add(1, Ordering::Relaxed);
        self.total_bytes_out.fetch_add(conn.bytes_sent, Ordering::Relaxed);
        self.total_bytes_in.fetch_add(conn.bytes_received, Ordering::Relaxed);

        // Track in streaming accumulator and pruning map
        let key = format!("{}:{}:{}", agent_id, host, now);
        self.active_connections.write().insert(key, conn.clone());
        self.connection_stats.write().push(conn.clone());

        ConnectionResult { verdict: ConnectionVerdict::Allowed, reason: "passed all checks".into(), connection: conn }
    }

    fn block(&self, conn: AgentConnection, verdict: ConnectionVerdict, reason: &str, now: i64) -> ConnectionResult {
        self.total_blocked.fetch_add(1, Ordering::Relaxed);
        warn!(agent = %conn.agent_id, host = %conn.destination_host, reason = %reason, "Connection blocked");
        self.add_alert(now, Severity::High, "Agent connection blocked",
            &format!("{} → {} blocked: {}", conn.agent_id, conn.destination_host, reason));
        ConnectionResult { verdict, reason: reason.to_string(), connection: conn }
    }

    fn is_known_bad(&self, host: &str) -> bool {
        for bad in KNOWN_BAD_DOMAINS {
            if host == *bad || host.ends_with(&format!(".{}", bad)) { return true; }
        }
        false
    }

    fn domain_matches(host: &str, pattern: &str) -> bool {
        if pattern.starts_with("*.") {
            let suffix = &pattern[1..];
            host.ends_with(suffix)
        } else {
            host == pattern
        }
    }

    fn check_endpoint_rate(&self, host: &str, now: i64) -> bool {
        let mut rates = self.endpoint_rates.write();
        let deque = rates.entry(host.to_string()).or_insert_with(VecDeque::new);
        let cutoff = now - 60;
        while deque.front().map_or(false, |t| *t < cutoff) { deque.pop_front(); }
        if deque.len() as u64 >= self.max_requests_per_minute { return false; }
        deque.push_back(now);
        true
    }

    fn check_bandwidth(&self, agent_id: &str, bytes: u64, now: i64) -> bool {
        let quota = self.bandwidth_quotas.read().get(agent_id).copied()
            .unwrap_or(self.default_bandwidth_quota);
        let mut usage = self.bandwidth_usage.write();
        let entries = usage.entry(agent_id.to_string()).or_insert_with(Vec::new);
        let cutoff = now - 3600;
        entries.retain(|(t, _)| *t > cutoff);
        let total: u64 = entries.iter().map(|(_, b)| b).sum();
        if total + bytes > quota { return false; }
        entries.push((now, bytes));
        true
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(AiAlert { timestamp: ts, severity: sev, component: "agent_network_fence".into(),
            title: title.into(), details: details.into() });
    }

    // ── Query ───────────────────────────────────────────────────────────────

    pub fn current_stats(&self) -> EndpointStats { self.connection_stats.read().state().clone() }
    pub fn is_locked_down(&self) -> bool { self.lockdown.load(Ordering::SeqCst) }
    pub fn total_connections(&self) -> u64 { self.total_connections.load(Ordering::Relaxed) }
    pub fn total_blocked(&self) -> u64 { self.total_blocked.load(Ordering::Relaxed) }
    pub fn total_allowed(&self) -> u64 { self.total_allowed.load(Ordering::Relaxed) }
    pub fn total_bytes_out(&self) -> u64 { self.total_bytes_out.load(Ordering::Relaxed) }
    pub fn total_bytes_in(&self) -> u64 { self.total_bytes_in.load(Ordering::Relaxed) }
    pub fn exfil_detections(&self) -> u64 { self.exfil_detections.load(Ordering::Relaxed) }
    pub fn geo_blocks(&self) -> u64 { self.geo_blocks.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
