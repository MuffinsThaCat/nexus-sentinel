//! # TLS Probe — Real TLS connection probe
//!
//! Connects to a host:port, performs a TLS handshake, and extracts the
//! negotiated protocol version and cipher suite for the TLS auditor.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use tracing::{info, warn, error};

/// Result of a real TLS probe.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TlsProbeResult {
    pub host: String,
    pub port: u16,
    pub connected: bool,
    pub protocol_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub certificate_subject: Option<String>,
    pub certificate_issuer: Option<String>,
    pub certificate_not_after: Option<String>,
    pub error: Option<String>,
    pub probe_duration_ms: u64,
}

/// Probes a host's TLS configuration by sending a ClientHello and parsing the ServerHello.
pub struct TlsProber {
    timeout: Duration,
}

impl TlsProber {
    pub fn new(timeout_secs: u64) -> Self {
        Self { timeout: Duration::from_secs(timeout_secs) }
    }

    /// Probe a single host:port via raw TLS ClientHello.
    pub fn probe(&self, host: &str, port: u16) -> TlsProbeResult {
        let start = std::time::Instant::now();
        let addr = format!("{}:{}", host, port);

        // Connect TCP
        let stream = match TcpStream::connect_timeout(
            &addr.parse().unwrap_or_else(|_| {
                // DNS resolution fallback
                use std::net::ToSocketAddrs;
                addr.to_socket_addrs()
                    .ok()
                    .and_then(|mut addrs| addrs.next())
                    .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap())
            }),
            self.timeout,
        ) {
            Ok(s) => s,
            Err(e) => {
                return TlsProbeResult {
                    host: host.into(), port, connected: false,
                    protocol_version: None, cipher_suite: None,
                    certificate_subject: None, certificate_issuer: None,
                    certificate_not_after: None,
                    error: Some(format!("TCP connect failed: {}", e)),
                    probe_duration_ms: start.elapsed().as_millis() as u64,
                };
            }
        };

        let _ = stream.set_read_timeout(Some(self.timeout));
        let _ = stream.set_write_timeout(Some(self.timeout));

        // Send a TLS 1.2 ClientHello with common cipher suites
        let client_hello = self.build_client_hello(host);
        let mut stream = stream;
        if let Err(e) = stream.write_all(&client_hello) {
            return TlsProbeResult {
                host: host.into(), port, connected: true,
                protocol_version: None, cipher_suite: None,
                certificate_subject: None, certificate_issuer: None,
                certificate_not_after: None,
                error: Some(format!("Write failed: {}", e)),
                probe_duration_ms: start.elapsed().as_millis() as u64,
            };
        }

        // Read ServerHello
        let mut buf = vec![0u8; 4096];
        let n = match stream.read(&mut buf) {
            Ok(n) => n,
            Err(e) => {
                return TlsProbeResult {
                    host: host.into(), port, connected: true,
                    protocol_version: None, cipher_suite: None,
                    certificate_subject: None, certificate_issuer: None,
                    certificate_not_after: None,
                    error: Some(format!("Read failed: {}", e)),
                    probe_duration_ms: start.elapsed().as_millis() as u64,
                };
            }
        };

        // Parse ServerHello
        let (proto, cipher) = self.parse_server_hello(&buf[..n]);

        info!(host, port, proto = ?proto, cipher = ?cipher, "TLS probe complete");

        TlsProbeResult {
            host: host.into(), port, connected: true,
            protocol_version: proto,
            cipher_suite: cipher,
            certificate_subject: None,
            certificate_issuer: None,
            certificate_not_after: None,
            error: None,
            probe_duration_ms: start.elapsed().as_millis() as u64,
        }
    }

    /// Probe multiple hosts in parallel.
    pub async fn probe_many(&self, targets: &[(String, u16)]) -> Vec<TlsProbeResult> {
        let timeout = self.timeout;
        let mut handles = Vec::new();

        for (host, port) in targets {
            let h = host.clone();
            let p = *port;
            let t = timeout;
            handles.push(tokio::task::spawn_blocking(move || {
                let prober = TlsProber::new(t.as_secs());
                prober.probe(&h, p)
            }));
        }

        let mut results = Vec::new();
        for handle in handles {
            if let Ok(result) = handle.await {
                results.push(result);
            }
        }
        results
    }

    /// Build a minimal TLS 1.2 ClientHello.
    fn build_client_hello(&self, hostname: &str) -> Vec<u8> {
        let mut hello: Vec<u8> = Vec::new();

        // Cipher suites we offer (to detect what server picks)
        let cipher_suites: &[u16] = &[
            0x1301, // TLS_AES_128_GCM_SHA256 (TLS 1.3)
            0x1302, // TLS_AES_256_GCM_SHA384 (TLS 1.3)
            0x1303, // TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3)
            0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xCCA9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
            0xCCA8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
            0x009E, // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
            0x009F, // TLS_DHE_RSA_WITH_AES_256_GCM_SHA256
            0x002F, // TLS_RSA_WITH_AES_128_CBC_SHA
            0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
        ];

        // ClientHello body
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 (for compat)

        // Random (32 bytes)
        let random: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        body.extend_from_slice(&random);

        // Session ID (empty)
        body.push(0);

        // Cipher suites
        let cs_len = (cipher_suites.len() * 2) as u16;
        body.extend_from_slice(&cs_len.to_be_bytes());
        for cs in cipher_suites {
            body.extend_from_slice(&cs.to_be_bytes());
        }

        // Compression methods (null only)
        body.push(1);
        body.push(0);

        // Extensions
        let mut extensions = Vec::new();

        // SNI extension
        let sni_name = hostname.as_bytes();
        let sni_list_len = (sni_name.len() + 3) as u16;
        let sni_ext_len = (sni_list_len + 2) as u16;
        extensions.extend_from_slice(&[0x00, 0x00]); // SNI type
        extensions.extend_from_slice(&sni_ext_len.to_be_bytes());
        extensions.extend_from_slice(&sni_list_len.to_be_bytes());
        extensions.push(0); // host name type
        extensions.extend_from_slice(&(sni_name.len() as u16).to_be_bytes());
        extensions.extend_from_slice(sni_name);

        // Supported versions extension (for TLS 1.3 detection)
        extensions.extend_from_slice(&[0x00, 0x2B]); // supported_versions
        extensions.extend_from_slice(&[0x00, 0x05]); // length
        extensions.push(4); // list length
        extensions.extend_from_slice(&[0x03, 0x04]); // TLS 1.3
        extensions.extend_from_slice(&[0x03, 0x03]); // TLS 1.2

        let ext_len = extensions.len() as u16;
        body.extend_from_slice(&ext_len.to_be_bytes());
        body.extend_from_slice(&extensions);

        // Handshake header
        let mut handshake = Vec::new();
        handshake.push(0x01); // ClientHello
        let hs_len = body.len() as u32;
        handshake.push((hs_len >> 16) as u8);
        handshake.push((hs_len >> 8) as u8);
        handshake.push(hs_len as u8);
        handshake.extend_from_slice(&body);

        // TLS record
        let mut record = Vec::new();
        record.push(0x16); // Handshake
        record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record layer (compat)
        let rec_len = handshake.len() as u16;
        record.extend_from_slice(&rec_len.to_be_bytes());
        record.extend_from_slice(&handshake);

        record
    }

    /// Parse a ServerHello response to extract protocol version and cipher suite.
    fn parse_server_hello(&self, data: &[u8]) -> (Option<String>, Option<String>) {
        if data.len() < 5 { return (None, None); }

        // Check for TLS record
        if data[0] != 0x16 { // Not a Handshake record
            if data[0] == 0x15 { // Alert
                return (Some("Alert received".into()), None);
            }
            return (None, None);
        }

        let record_version = format!("{}.{}", data[1], data[2]);

        // Skip record header (5 bytes), get handshake type
        if data.len() < 6 || data[5] != 0x02 { // Not ServerHello
            return (Some(format!("TLS record {}", record_version)), None);
        }

        // Parse ServerHello
        if data.len() < 44 { return (Some(format!("TLS {}", record_version)), None); }

        let server_version_major = data[9];
        let server_version_minor = data[10];

        let proto = match (server_version_major, server_version_minor) {
            (3, 4) => "TLSv1.3",
            (3, 3) => "TLSv1.2",
            (3, 2) => "TLSv1.1",
            (3, 1) => "TLSv1.0",
            (3, 0) => "SSLv3",
            (2, 0) => "SSLv2",
            _ => "Unknown",
        };

        // Skip random (32 bytes at offset 11-42)
        let session_id_len = data[43] as usize;
        let cipher_offset = 44 + session_id_len;

        if data.len() < cipher_offset + 2 {
            return (Some(proto.into()), None);
        }

        let cipher_suite = u16::from_be_bytes([data[cipher_offset], data[cipher_offset + 1]]);
        let cipher_name = self.cipher_suite_name(cipher_suite);

        // Check for TLS 1.3 via supported_versions extension
        let mut actual_proto = proto.to_string();
        if proto == "TLSv1.2" {
            // TLS 1.3 uses 0x0303 in ServerHello but has supported_versions extension
            let ext_start = cipher_offset + 3; // +2 cipher +1 compression
            if data.len() > ext_start + 2 {
                let ext_len = u16::from_be_bytes([data[ext_start], data[ext_start + 1]]) as usize;
                let mut pos = ext_start + 2;
                while pos + 4 < data.len().min(ext_start + 2 + ext_len) {
                    let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
                    let ext_data_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
                    if ext_type == 0x002B && ext_data_len >= 2 { // supported_versions
                        let sv_major = data[pos + 4];
                        let sv_minor = data[pos + 5];
                        if sv_major == 3 && sv_minor == 4 {
                            actual_proto = "TLSv1.3".into();
                        }
                    }
                    pos += 4 + ext_data_len;
                }
            }
        }

        (Some(actual_proto), Some(cipher_name))
    }

    fn cipher_suite_name(&self, id: u16) -> String {
        match id {
            0x1301 => "TLS_AES_128_GCM_SHA256".into(),
            0x1302 => "TLS_AES_256_GCM_SHA384".into(),
            0x1303 => "TLS_CHACHA20_POLY1305_SHA256".into(),
            0xC02C => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".into(),
            0xC02B => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".into(),
            0xC030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".into(),
            0xC02F => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".into(),
            0xCCA9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305".into(),
            0xCCA8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305".into(),
            0x009E => "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256".into(),
            0x009F => "TLS_DHE_RSA_WITH_AES_256_GCM_SHA256".into(),
            0x002F => "TLS_RSA_WITH_AES_128_CBC_SHA".into(),
            0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA".into(),
            0x000A => "TLS_RSA_WITH_3DES_EDE_CBC_SHA".into(),
            0x0004 => "TLS_RSA_WITH_RC4_128_MD5".into(),
            0x0005 => "TLS_RSA_WITH_RC4_128_SHA".into(),
            other => format!("0x{:04X}", other),
        }
    }
}
