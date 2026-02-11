//! # Packet Capture Adapter — Real network interface sniffing
//!
//! Uses pnet to capture raw packets from a network interface, parses them
//! into FlowRecords, and feeds them into the event bus.

use crate::event_bus::{EventBus, EventSeverity};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{error, info, warn};

/// Parsed packet from raw capture.
#[derive(Debug, Clone)]
pub struct CapturedPacket {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8, // IANA protocol number
    pub length: u32,
    pub timestamp_ms: i64,
    pub tcp_flags: u8,
    pub payload_preview: Vec<u8>, // first 128 bytes
}

/// Flow aggregation key.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct FlowKey {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
}

/// Aggregated flow state.
#[derive(Debug, Clone)]
struct FlowState {
    bytes: u64,
    packets: u64,
    first_seen: i64,
    last_seen: i64,
    tcp_flags_seen: u8,
}

/// Real packet capture adapter.
pub struct PacketCaptureAdapter {
    interface: String,
    running: Arc<AtomicBool>,
    packets_captured: Arc<AtomicU64>,
    bytes_captured: Arc<AtomicU64>,
    flows_emitted: Arc<AtomicU64>,
    active_flows: Arc<RwLock<HashMap<FlowKey, FlowState>>>,
    flow_timeout_secs: i64,
}

impl PacketCaptureAdapter {
    pub fn new(interface: &str) -> Self {
        Self {
            interface: interface.into(),
            running: Arc::new(AtomicBool::new(false)),
            packets_captured: Arc::new(AtomicU64::new(0)),
            bytes_captured: Arc::new(AtomicU64::new(0)),
            flows_emitted: Arc::new(AtomicU64::new(0)),
            active_flows: Arc::new(RwLock::new(HashMap::new())),
            flow_timeout_secs: 30,
        }
    }

    /// List available network interfaces.
    pub fn list_interfaces() -> Vec<String> {
        pnet::datalink::interfaces()
            .iter()
            .filter(|iface| iface.is_up() && !iface.is_loopback())
            .map(|iface| format!("{} ({})", iface.name, iface.description))
            .collect()
    }

    /// Start packet capture in a background task.
    pub fn start(&self, bus: Arc<EventBus>) -> Result<(), String> {
        let interfaces = pnet::datalink::interfaces();
        let iface = interfaces.iter()
            .find(|i| i.name == self.interface)
            .ok_or_else(|| format!("Interface '{}' not found. Available: {:?}",
                self.interface,
                interfaces.iter().map(|i| &i.name).collect::<Vec<_>>()))?;

        self.running.store(true, Ordering::Relaxed);
        let running = self.running.clone();
        let packets_counter = self.packets_captured.clone();
        let bytes_counter = self.bytes_captured.clone();
        let flows_counter = self.flows_emitted.clone();
        let active_flows = self.active_flows.clone();
        let flow_timeout = self.flow_timeout_secs;
        let iface_name = iface.name.clone();

        // Create the datalink channel
        let config = pnet::datalink::Config {
            read_timeout: Some(std::time::Duration::from_secs(1)),
            ..Default::default()
        };

        let (_tx, mut rx) = match pnet::datalink::channel(&iface, config) {
            Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err("Unsupported channel type".into()),
            Err(e) => return Err(format!("Failed to open capture: {}", e)),
        };

        info!(interface = %iface_name, "Packet capture started");

        std::thread::spawn(move || {
            let mut last_flush = chrono::Utc::now().timestamp();

            while running.load(Ordering::Relaxed) {
                match rx.next() {
                    Ok(packet) => {
                        let now = chrono::Utc::now().timestamp_millis();
                        packets_counter.fetch_add(1, Ordering::Relaxed);
                        bytes_counter.fetch_add(packet.len() as u64, Ordering::Relaxed);

                        // Parse Ethernet → IP → TCP/UDP
                        if let Some(parsed) = Self::parse_ethernet(packet, now) {
                            let key = FlowKey {
                                src_ip: parsed.src_ip,
                                dst_ip: parsed.dst_ip,
                                src_port: parsed.src_port,
                                dst_port: parsed.dst_port,
                                protocol: parsed.protocol,
                            };

                            let mut flows = active_flows.write();
                            let entry = flows.entry(key).or_insert_with(|| FlowState {
                                bytes: 0, packets: 0,
                                first_seen: now, last_seen: now,
                                tcp_flags_seen: 0,
                            });
                            entry.bytes += parsed.length as u64;
                            entry.packets += 1;
                            entry.last_seen = now;
                            entry.tcp_flags_seen |= parsed.tcp_flags;
                        }

                        // Periodic flow flush
                        let now_secs = chrono::Utc::now().timestamp();
                        if now_secs - last_flush >= flow_timeout {
                            let mut flows = active_flows.write();
                            let cutoff = now_secs * 1000 - (flow_timeout * 1000);
                            let expired: Vec<(FlowKey, FlowState)> = flows.iter()
                                .filter(|(_, v)| v.last_seen < cutoff)
                                .map(|(k, v)| (k.clone(), v.clone()))
                                .collect();

                            for (key, state) in &expired {
                                flows.remove(key);
                                flows_counter.fetch_add(1, Ordering::Relaxed);

                                // Emit to event bus
                                let mut details = HashMap::new();
                                details.insert("src_ip".into(), key.src_ip.to_string());
                                details.insert("dst_ip".into(), key.dst_ip.to_string());
                                details.insert("src_port".into(), key.src_port.to_string());
                                details.insert("dst_port".into(), key.dst_port.to_string());
                                details.insert("protocol".into(), key.protocol.to_string());
                                details.insert("bytes".into(), state.bytes.to_string());
                                details.insert("packets".into(), state.packets.to_string());

                                bus.emit_detection(
                                    "packet_capture", "sentinel-core",
                                    EventSeverity::Info, "Network flow completed",
                                    details, vec!["network".into(), "flow".into()],
                                );
                            }
                            last_flush = now_secs;
                        }
                    }
                    Err(e) => {
                        // Timeout is normal with read_timeout set
                        if !e.to_string().contains("timed out") {
                            warn!(error = %e, "Packet capture error");
                        }
                    }
                }
            }
            info!(interface = %iface_name, "Packet capture stopped");
        });

        Ok(())
    }

    /// Parse raw Ethernet frame into a CapturedPacket.
    fn parse_ethernet(data: &[u8], timestamp_ms: i64) -> Option<CapturedPacket> {
        if data.len() < 14 { return None; }

        // Ethernet header: 6 dst + 6 src + 2 ethertype
        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        if ethertype != 0x0800 { return None; } // IPv4 only

        let ip_start = 14;
        if data.len() < ip_start + 20 { return None; }

        let version_ihl = data[ip_start];
        let ihl = ((version_ihl & 0x0F) as usize) * 4;
        let protocol = data[ip_start + 9];
        let total_length = u16::from_be_bytes([data[ip_start + 2], data[ip_start + 3]]);

        let src_ip = IpAddr::V4(std::net::Ipv4Addr::new(
            data[ip_start + 12], data[ip_start + 13],
            data[ip_start + 14], data[ip_start + 15],
        ));
        let dst_ip = IpAddr::V4(std::net::Ipv4Addr::new(
            data[ip_start + 16], data[ip_start + 17],
            data[ip_start + 18], data[ip_start + 19],
        ));

        let transport_start = ip_start + ihl;
        let (src_port, dst_port, tcp_flags) = if data.len() >= transport_start + 4 {
            let sp = u16::from_be_bytes([data[transport_start], data[transport_start + 1]]);
            let dp = u16::from_be_bytes([data[transport_start + 2], data[transport_start + 3]]);
            let flags = if protocol == 6 && data.len() >= transport_start + 14 {
                data[transport_start + 13]
            } else { 0 };
            (sp, dp, flags)
        } else {
            (0, 0, 0)
        };

        let payload_start = if protocol == 6 {
            transport_start + ((data.get(transport_start + 12).unwrap_or(&0x50) >> 4) as usize * 4).min(60)
        } else if protocol == 17 {
            transport_start + 8
        } else {
            transport_start
        };

        let payload_preview = if data.len() > payload_start {
            data[payload_start..data.len().min(payload_start + 128)].to_vec()
        } else {
            Vec::new()
        };

        Some(CapturedPacket {
            src_ip, dst_ip, src_port, dst_port,
            protocol, length: total_length as u32,
            timestamp_ms, tcp_flags, payload_preview,
        })
    }

    pub fn stop(&self) { self.running.store(false, Ordering::Relaxed); }
    pub fn packets_captured(&self) -> u64 { self.packets_captured.load(Ordering::Relaxed) }
    pub fn bytes_captured(&self) -> u64 { self.bytes_captured.load(Ordering::Relaxed) }
    pub fn flows_emitted(&self) -> u64 { self.flows_emitted.load(Ordering::Relaxed) }
    pub fn active_flow_count(&self) -> usize { self.active_flows.read().len() }
    pub fn is_running(&self) -> bool { self.running.load(Ordering::Relaxed) }
}
