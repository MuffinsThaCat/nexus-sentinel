//! # Network Connection Tracker — Real-time socket enumeration
//!
//! Uses `sysinfo` and `/proc/net` (Linux) or `netstat`-equivalent APIs to enumerate
//! all active TCP/UDP connections on the host, detect anomalous connections,
//! and cross-reference against threat intelligence IOCs.

use crate::event_bus::{EventBus, EventSeverity};
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use sysinfo::{System, Networks};
use tracing::{info, warn};

/// A live network connection.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LiveConnection {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub protocol: String,
    pub state: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub first_seen: i64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}

/// Anomalous connection finding.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConnectionAnomaly {
    pub connection: LiveConnection,
    pub reason: String,
    pub severity: ConnSeverity,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum ConnSeverity { Low, Medium, High, Critical }

/// Well-known ports that should NOT have outbound connections from user processes.
const SUSPICIOUS_OUTBOUND_PORTS: &[(u16, &str)] = &[
    (4444, "meterpreter_default"),
    (5555, "android_debug"),
    (6666, "irc_backdoor"),
    (6667, "irc_c2"),
    (8888, "common_backdoor"),
    (9999, "common_backdoor"),
    (1080, "socks_proxy"),
    (3128, "squid_proxy"),
    (8080, "http_proxy"),
    (31337, "elite_backdoor"),
    (12345, "netbus"),
    (27374, "sub7"),
    (1337, "waste"),
];

/// Private/RFC1918 ranges.
fn is_private_ip(ip: &str) -> bool {
    if let Ok(addr) = ip.parse::<Ipv4Addr>() {
        let octets = addr.octets();
        return matches!(octets[0], 10) ||
               (octets[0] == 172 && (16..=31).contains(&octets[1])) ||
               (octets[0] == 192 && octets[1] == 168) ||
               (octets[0] == 127);
    }
    ip == "::1" || ip.starts_with("fe80") || ip.starts_with("fd")
}

/// Countries associated with high-risk C2 infrastructure (by IP range heuristic).
/// In production, this would use a GeoIP database.
const DNS_OVER_HTTPS_PORTS: &[u16] = &[443, 853];

/// Real-time network connection tracker.
pub struct NetConnectionTracker {
    /// Current snapshot of connections
    connections: Arc<RwLock<Vec<LiveConnection>>>,
    /// Historical anomalies
    anomalies: RwLock<Vec<ConnectionAnomaly>>,
    /// Whitelisted remote IPs
    whitelist: RwLock<HashSet<String>>,
    /// Blacklisted remote IPs (from threat intel)
    blacklist: RwLock<HashSet<String>>,
    /// Known service ports per process
    known_listeners: RwLock<HashMap<String, HashSet<u16>>>,
    /// Counters
    scans_completed: AtomicU64,
    connections_seen: AtomicU64,
    anomalies_found: AtomicU64,
    running: Arc<AtomicBool>,
    max_anomalies: usize,
}

impl NetConnectionTracker {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(Vec::new())),
            anomalies: RwLock::new(Vec::new()),
            whitelist: RwLock::new(HashSet::new()),
            blacklist: RwLock::new(HashSet::new()),
            known_listeners: RwLock::new(HashMap::new()),
            scans_completed: AtomicU64::new(0),
            connections_seen: AtomicU64::new(0),
            anomalies_found: AtomicU64::new(0),
            running: Arc::new(AtomicBool::new(false)),
            max_anomalies: 50_000,
        }
    }

    /// Add an IP to the whitelist.
    pub fn whitelist_ip(&self, ip: &str) {
        self.whitelist.write().insert(ip.to_string());
    }

    /// Add an IP to the blacklist (e.g., from threat intel).
    pub fn blacklist_ip(&self, ip: &str) {
        self.blacklist.write().insert(ip.to_string());
    }

    /// Bulk-load blacklisted IPs from threat intel.
    pub fn load_blacklist(&self, ips: &[String]) {
        let mut bl = self.blacklist.write();
        for ip in ips {
            bl.insert(ip.clone());
        }
        info!(count = ips.len(), "Loaded blacklisted IPs from threat intel");
    }

    /// Enumerate live connections by parsing /proc/net/tcp (Linux) or
    /// using lsof-style enumeration. Cross-platform via command output parsing.
    pub fn scan(&self) -> Vec<LiveConnection> {
        self.scans_completed.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();

        let mut connections = Vec::new();

        // Use netstat-style output parsing (cross-platform)
        #[cfg(target_os = "linux")]
        {
            if let Ok(output) = std::process::Command::new("ss")
                .args(["-tunapo"])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines().skip(1) {
                    if let Some(conn) = Self::parse_ss_line(line, now) {
                        connections.push(conn);
                    }
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            // Use lsof for macOS — more reliable than netstat
            if let Ok(output) = std::process::Command::new("lsof")
                .args(["-i", "-n", "-P", "+c", "0"])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines().skip(1) {
                    if let Some(conn) = Self::parse_lsof_line(line, now) {
                        connections.push(conn);
                    }
                }
            }
        }

        self.connections_seen.fetch_add(connections.len() as u64, Ordering::Relaxed);
        *self.connections.write() = connections.clone();
        connections
    }

    /// Parse an `ss` output line (Linux).
    #[cfg(target_os = "linux")]
    fn parse_ss_line(line: &str, now: i64) -> Option<LiveConnection> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 { return None; }

        let proto = parts[0].to_string();
        let state = parts[1].to_string();
        let local = parts[4];
        let remote = parts[5];

        let (local_addr, local_port) = Self::split_addr_port(local)?;
        let (remote_addr, remote_port) = Self::split_addr_port(remote)?;

        // Try to extract PID from the users: column
        let pid = parts.get(6).and_then(|s| {
            s.split("pid=").nth(1).and_then(|p| p.split(',').next()).and_then(|p| p.parse().ok())
        });

        Some(LiveConnection {
            local_addr, local_port, remote_addr, remote_port,
            protocol: proto, state, pid, process_name: None,
            first_seen: now, bytes_sent: 0, bytes_recv: 0,
        })
    }

    /// Parse an `lsof` output line (macOS).
    #[cfg(target_os = "macos")]
    fn parse_lsof_line(line: &str, now: i64) -> Option<LiveConnection> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 9 { return None; }

        let process_name = parts[0].to_string();
        let pid: u32 = parts[1].parse().ok()?;
        let proto_field = parts.get(7).unwrap_or(&"");
        let name_field = parts.last().unwrap_or(&"");

        // Parse "host:port->host:port" or "host:port"
        let protocol = if proto_field.contains("TCP") { "tcp" }
                       else if proto_field.contains("UDP") { "udp" }
                       else { return None; }.to_string();

        if let Some((local, remote)) = name_field.split_once("->") {
            let (local_addr, local_port) = Self::split_addr_port(local)?;
            let (remote_addr, remote_port) = Self::split_addr_port(remote)?;

            let state = if name_field.contains("ESTABLISHED") { "ESTABLISHED" }
                       else if name_field.contains("LISTEN") { "LISTEN" }
                       else if name_field.contains("CLOSE_WAIT") { "CLOSE_WAIT" }
                       else { "UNKNOWN" }.to_string();

            Some(LiveConnection {
                local_addr, local_port, remote_addr, remote_port,
                protocol, state, pid: Some(pid),
                process_name: Some(process_name),
                first_seen: now, bytes_sent: 0, bytes_recv: 0,
            })
        } else {
            // Listening socket
            let (local_addr, local_port) = Self::split_addr_port(name_field)?;
            Some(LiveConnection {
                local_addr, local_port,
                remote_addr: "*".into(), remote_port: 0,
                protocol, state: "LISTEN".into(), pid: Some(pid),
                process_name: Some(process_name),
                first_seen: now, bytes_sent: 0, bytes_recv: 0,
            })
        }
    }

    /// Split "addr:port" into (addr, port).
    fn split_addr_port(s: &str) -> Option<(String, u16)> {
        if let Some(pos) = s.rfind(':') {
            let addr = s[..pos].trim_matches(['[', ']']).to_string();
            let port: u16 = s[pos+1..].trim_matches(|c: char| !c.is_ascii_digit()).parse().ok()?;
            Some((addr, port))
        } else {
            None
        }
    }

    /// Analyze connections for anomalies.
    pub fn analyze(&self) -> Vec<ConnectionAnomaly> {
        let connections = self.connections.read().clone();
        let whitelist = self.whitelist.read();
        let blacklist = self.blacklist.read();
        let mut anomalies = Vec::new();

        for conn in &connections {
            // Skip whitelisted
            if whitelist.contains(&conn.remote_addr) { continue; }

            // 1. Blacklisted IP (from threat intel)
            if blacklist.contains(&conn.remote_addr) {
                anomalies.push(ConnectionAnomaly {
                    connection: conn.clone(),
                    reason: format!("Connection to blacklisted IP {} (threat intel match)", conn.remote_addr),
                    severity: ConnSeverity::Critical,
                });
                continue;
            }

            // 2. Known C2/backdoor ports
            for (port, label) in SUSPICIOUS_OUTBOUND_PORTS {
                if conn.remote_port == *port && conn.state == "ESTABLISHED" {
                    anomalies.push(ConnectionAnomaly {
                        connection: conn.clone(),
                        reason: format!("Outbound to suspicious port {} ({})", port, label),
                        severity: ConnSeverity::High,
                    });
                }
            }

            // 3. Non-standard outbound from system processes
            if let Some(ref name) = conn.process_name {
                let name_lower = name.to_lowercase();
                // System processes making unexpected outbound connections
                if (name_lower == "sshd" || name_lower == "cron" || name_lower == "systemd")
                    && !is_private_ip(&conn.remote_addr)
                    && conn.state == "ESTABLISHED"
                {
                    anomalies.push(ConnectionAnomaly {
                        connection: conn.clone(),
                        reason: format!("System process '{}' connecting to external IP {}", name, conn.remote_addr),
                        severity: ConnSeverity::High,
                    });
                }
            }

            // 4. Connections to raw IP (no DNS resolution happened)
            if conn.remote_addr.parse::<IpAddr>().is_ok()
                && !is_private_ip(&conn.remote_addr)
                && conn.state == "ESTABLISHED"
                && conn.remote_port != 443
                && conn.remote_port != 80
            {
                // Direct IP connections on non-standard ports = suspicious
                if conn.remote_port > 1024 {
                    anomalies.push(ConnectionAnomaly {
                        connection: conn.clone(),
                        reason: format!("Direct IP connection to {}:{} (no DNS, high port)", conn.remote_addr, conn.remote_port),
                        severity: ConnSeverity::Medium,
                    });
                }
            }

            // 5. DNS over HTTPS evasion detection
            if DNS_OVER_HTTPS_PORTS.contains(&conn.remote_port) {
                if let Some(ref name) = conn.process_name {
                    let n = name.to_lowercase();
                    if n.contains("dns") || n.contains("resolve") || n.contains("doh") {
                        anomalies.push(ConnectionAnomaly {
                            connection: conn.clone(),
                            reason: format!("Potential DNS-over-HTTPS evasion by '{}'", name),
                            severity: ConnSeverity::Medium,
                        });
                    }
                }
            }
        }

        // Store anomalies
        self.anomalies_found.fetch_add(anomalies.len() as u64, Ordering::Relaxed);
        {
            let mut stored = self.anomalies.write();
            for a in &anomalies {
                if stored.len() >= self.max_anomalies {
                    let drain = self.max_anomalies / 4;
                    stored.drain(..drain);
                }
                stored.push(a.clone());
            }
        }

        anomalies
    }

    /// Start periodic scanning with event bus integration.
    pub fn start_periodic(&self, interval_secs: u64, bus: Arc<EventBus>) {
        self.running.store(true, Ordering::Relaxed);
        let running = self.running.clone();
        let connections = self.connections.clone();
        let blacklist_ref = self.blacklist.read().clone();

        info!(interval_secs, "Network connection tracker started");

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            while running.load(Ordering::Relaxed) {
                ticker.tick().await;

                // Scan connections
                let now = chrono::Utc::now().timestamp();

                #[cfg(target_os = "macos")]
                let conns = {
                    let output = tokio::process::Command::new("lsof")
                        .args(["-i", "-n", "-P", "+c", "0"])
                        .output().await;
                    match output {
                        Ok(out) => {
                            let stdout = String::from_utf8_lossy(&out.stdout);
                            let mut result = Vec::new();
                            for line in stdout.lines().skip(1) {
                                if let Some(conn) = Self::parse_lsof_line(line, now) {
                                    result.push(conn);
                                }
                            }
                            result
                        }
                        Err(_) => Vec::new(),
                    }
                };

                #[cfg(not(target_os = "macos"))]
                let conns = Vec::<LiveConnection>::new();

                // Check against blacklist and emit events
                for conn in &conns {
                    if blacklist_ref.contains(&conn.remote_addr) {
                        let mut details = HashMap::new();
                        details.insert("remote_ip".into(), conn.remote_addr.clone());
                        details.insert("remote_port".into(), conn.remote_port.to_string());
                        details.insert("process".into(), conn.process_name.clone().unwrap_or_default());
                        bus.emit_detection(
                            "net_connection_tracker", "sentinel-core",
                            EventSeverity::Critical,
                            "Connection to threat-intel blacklisted IP",
                            details,
                            vec!["network".into(), "c2".into(), "threat_intel".into()],
                        );
                    }
                }

                *connections.write() = conns;
            }
        });
    }

    pub fn stop(&self) { self.running.store(false, Ordering::Relaxed); }
    pub fn current_connections(&self) -> Vec<LiveConnection> { self.connections.read().clone() }
    pub fn recent_anomalies(&self, count: usize) -> Vec<ConnectionAnomaly> {
        let a = self.anomalies.read();
        let start = a.len().saturating_sub(count);
        a[start..].to_vec()
    }
    pub fn scans_completed(&self) -> u64 { self.scans_completed.load(Ordering::Relaxed) }
    pub fn total_anomalies(&self) -> u64 { self.anomalies_found.load(Ordering::Relaxed) }
    pub fn is_running(&self) -> bool { self.running.load(Ordering::Relaxed) }
    pub fn blacklist_size(&self) -> usize { self.blacklist.read().len() }
}
