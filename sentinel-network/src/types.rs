use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};

/// Network traffic direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Direction {
    Inbound,
    Outbound,
    Internal,
}

/// Transport protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

/// A network flow record — the fundamental unit of network security analysis.
/// Uses Breakthroughs #5 (streaming) and #4 (VQ codec) for compact representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowRecord {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub direction: Direction,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub start_time: i64,
    pub end_time: i64,
    pub flags: u8,
}

impl FlowRecord {
    /// Convert to f32 feature vector for VQ codec compression.
    pub fn to_feature_vec(&self) -> Vec<f32> {
        let src = match self.src_ip {
            IpAddr::V4(ip) => {
                let octets = ip.octets();
                vec![
                    octets[0] as f32,
                    octets[1] as f32,
                    octets[2] as f32,
                    octets[3] as f32,
                ]
            }
            IpAddr::V6(_) => vec![0.0; 4],
        };
        let dst = match self.dst_ip {
            IpAddr::V4(ip) => {
                let octets = ip.octets();
                vec![
                    octets[0] as f32,
                    octets[1] as f32,
                    octets[2] as f32,
                    octets[3] as f32,
                ]
            }
            IpAddr::V6(_) => vec![0.0; 4],
        };
        vec![
            src[0], src[1], src[2], src[3],
            dst[0], dst[1], dst[2], dst[3],
            self.src_port as f32,
            self.dst_port as f32,
            self.bytes_sent as f32,
            self.bytes_recv as f32,
            self.packets_sent as f32,
            self.packets_recv as f32,
            self.flags as f32,
            match self.protocol {
                Protocol::Tcp => 6.0,
                Protocol::Udp => 17.0,
                Protocol::Icmp => 1.0,
                Protocol::Other(n) => n as f32,
            },
        ]
    }
}

impl Into<Vec<f32>> for FlowRecord {
    fn into(self) -> Vec<f32> {
        self.to_feature_vec()
    }
}

/// Firewall rule action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FirewallAction {
    Allow,
    Deny,
    Log,
    RateLimit,
}

/// A firewall rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub id: u32,
    pub name: String,
    pub src_cidr: Option<String>,
    pub dst_cidr: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Option<Protocol>,
    pub direction: Direction,
    pub action: FirewallAction,
    pub priority: u32,
    pub enabled: bool,
    pub hit_count: u64,
}

/// IDS/IPS alert severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// An IDS/IPS alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: u64,
    pub timestamp: i64,
    pub severity: Severity,
    pub rule_id: u32,
    pub rule_name: String,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub message: String,
    pub payload_sample: Option<Vec<u8>>,
}

/// Network interface stats
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InterfaceStats {
    pub name: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub errors_in: u64,
    pub errors_out: u64,
    pub drops: u64,
}

/// Connection state for stateful tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConnectionState {
    New,
    Established,
    Related,
    Closing,
    Closed,
    Invalid,
}

/// A tracked connection in the connection table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedConnection {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub state: ConnectionState,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub start_time: i64,
    pub last_seen: i64,
}
