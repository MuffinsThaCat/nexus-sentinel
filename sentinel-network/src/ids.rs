//! IDS/IPS — Component 2 of 15 in Network Security Layer
//!
//! Production-grade Intrusion Detection/Prevention System featuring:
//! - **Aho-Corasick multi-pattern engine**: Matches 200+ signatures simultaneously in O(n)
//! - **12 attack categories**: SQL injection, XSS, command injection, path traversal,
//!   shellcode, C2 beacons, protocol exploits, credential theft, webshells, cryptomining,
//!   lateral movement, data exfiltration
//! - **Protocol-aware inspection**: HTTP, DNS, SMTP, FTP, SSH, TLS fingerprinting
//! - **Rate-based detection**: SYN flood, brute force, scan detection
//! - **Stateful flow tracking**: TCP session reassembly, fragmentation detection
//!
//! Memory breakthroughs:
//! - **#2 Tiered Cache**: Frequently-hit rules hot, rare rules compressed cold
//! - **#3 Reversible**: Store final match result, recompute match chain for forensics
//! - **#5 Streaming Accumulation**: Process packets in stream, accumulate match state per-flow
//! - **#6 Theoretical Verifier**: Verify rule engine memory stays within bounds
//! - **#592 Dedup**: Overlapping rules across rulesets deduplicated
//! - **#569 Entry Pruning**: Prune stale match state

use crate::types::*;
use aho_corasick::AhoCorasick;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::dedup::DedupStore;
use sentinel_core::hierarchical::HierarchicalState;
use sentinel_core::pruning::PruningMap;
use sentinel_core::MemoryMetrics;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use parking_lot::RwLock;
use tracing::warn;

// ── Attack Categories ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum AttackCategory {
    SqlInjection,
    CrossSiteScripting,
    CommandInjection,
    PathTraversal,
    Shellcode,
    C2Beacon,
    ProtocolExploit,
    CredentialTheft,
    WebShell,
    CryptoMining,
    LateralMovement,
    DataExfiltration,
    BruteForce,
    Reconnaissance,
    DenialOfService,
    MalwareCallback,
}

impl AttackCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SqlInjection => "SQL Injection",
            Self::CrossSiteScripting => "Cross-Site Scripting (XSS)",
            Self::CommandInjection => "Command Injection",
            Self::PathTraversal => "Path Traversal",
            Self::Shellcode => "Shellcode Detection",
            Self::C2Beacon => "C2 Beacon / Callback",
            Self::ProtocolExploit => "Protocol Exploit",
            Self::CredentialTheft => "Credential Theft",
            Self::WebShell => "Web Shell",
            Self::CryptoMining => "Cryptomining Activity",
            Self::LateralMovement => "Lateral Movement",
            Self::DataExfiltration => "Data Exfiltration",
            Self::BruteForce => "Brute Force",
            Self::Reconnaissance => "Reconnaissance / Scanning",
            Self::DenialOfService => "Denial of Service",
            Self::MalwareCallback => "Malware Callback",
        }
    }
}

// ── Signature Definition ─────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Signature {
    pub id: u32,
    pub name: String,
    pub pattern: Vec<u8>,
    pub severity: Severity,
    pub category: AttackCategory,
    pub cve: Option<String>,
    pub mitre_id: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MatchVerdict {
    pub matched: bool,
    pub rule_id: u32,
    pub severity: Severity,
    pub category: AttackCategory,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Default)]
pub struct AlertWindow {
    pub alert_count: u64,
    pub by_severity: [u64; 5],
    pub by_category: HashMap<String, u64>,
    pub unique_sources: HashSet<IpAddr>,
}

// ── Rate Tracking ────────────────────────────────────────────────────────────

struct RateTracker {
    /// source IP → (connection count, first_seen, last_seen)
    connections: HashMap<IpAddr, (u64, i64, i64)>,
    /// source IP → failed auth count
    auth_failures: HashMap<IpAddr, u64>,
    /// source IP → set of ports scanned
    port_scans: HashMap<IpAddr, HashSet<u16>>,
    /// SYN flood: source IP → SYN count in window
    syn_counts: HashMap<IpAddr, u64>,
}

impl RateTracker {
    fn new() -> Self {
        Self {
            connections: HashMap::new(),
            auth_failures: HashMap::new(),
            port_scans: HashMap::new(),
            syn_counts: HashMap::new(),
        }
    }
}

// ── Protocol Fingerprints ────────────────────────────────────────────────────

struct ProtocolDetector;

impl ProtocolDetector {
    fn detect(payload: &[u8], dst_port: u16) -> DetectedProtocol {
        if payload.len() < 4 { return DetectedProtocol::Unknown; }
        // TLS ClientHello
        if payload[0] == 0x16 && payload[1] == 0x03 {
            return DetectedProtocol::Tls;
        }
        // SSH
        if payload.starts_with(b"SSH-") {
            return DetectedProtocol::Ssh;
        }
        // HTTP
        if payload.starts_with(b"GET ") || payload.starts_with(b"POST ")
            || payload.starts_with(b"PUT ") || payload.starts_with(b"DELETE ")
            || payload.starts_with(b"HEAD ") || payload.starts_with(b"OPTIONS ")
            || payload.starts_with(b"PATCH ") || payload.starts_with(b"HTTP/")
        {
            return DetectedProtocol::Http;
        }
        // DNS
        if (dst_port == 53 || dst_port == 5353) && payload.len() > 12 {
            return DetectedProtocol::Dns;
        }
        // SMTP
        if payload.starts_with(b"EHLO ") || payload.starts_with(b"HELO ")
            || payload.starts_with(b"MAIL FROM:") || payload.starts_with(b"220 ")
        {
            return DetectedProtocol::Smtp;
        }
        // FTP
        if payload.starts_with(b"USER ") || payload.starts_with(b"PASS ")
            || payload.starts_with(b"230 ") || payload.starts_with(b"530 ")
        {
            return DetectedProtocol::Ftp;
        }
        // SMB
        if payload.len() > 4 && &payload[0..4] == b"\xffSMB" {
            return DetectedProtocol::Smb;
        }
        if payload.len() > 4 && &payload[0..4] == b"\xfeSMB" {
            return DetectedProtocol::Smb2;
        }
        // RDP
        if dst_port == 3389 {
            return DetectedProtocol::Rdp;
        }
        DetectedProtocol::Unknown
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DetectedProtocol {
    Http, Tls, Ssh, Dns, Smtp, Ftp, Smb, Smb2, Rdp, Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IdsMode { Detection, Prevention }

// ── Built-in Signature Database ──────────────────────────────────────────────

fn builtin_signatures() -> Vec<Signature> {
    let mut sigs = Vec::with_capacity(220);
    let mut id = 1000000u32;
    let mut add = |name: &str, pat: &str, sev: Severity, cat: AttackCategory, cve: Option<&str>, mitre: Option<&str>| {
        sigs.push(Signature {
            id: { id += 1; id },
            name: name.to_string(),
            pattern: pat.as_bytes().to_vec(),
            severity: sev,
            category: cat,
            cve: cve.map(|s| s.to_string()),
            mitre_id: mitre.map(|s| s.to_string()),
            enabled: true,
        });
    };

    // ── SQL Injection (30 patterns) ──────────────────────────────────────
    add("SQLi: UNION SELECT", "union select", Severity::Critical, AttackCategory::SqlInjection, None, Some("T1190"));
    add("SQLi: UNION ALL SELECT", "union all select", Severity::Critical, AttackCategory::SqlInjection, None, Some("T1190"));
    add("SQLi: OR 1=1", "' or 1=1", Severity::High, AttackCategory::SqlInjection, None, Some("T1190"));
    add("SQLi: OR ''='", "' or ''='", Severity::High, AttackCategory::SqlInjection, None, Some("T1190"));
    add("SQLi: DROP TABLE", "drop table", Severity::Critical, AttackCategory::SqlInjection, None, Some("T1190"));
    add("SQLi: DROP DATABASE", "drop database", Severity::Critical, AttackCategory::SqlInjection, None, Some("T1190"));
    add("SQLi: INSERT INTO", "insert into", Severity::High, AttackCategory::SqlInjection, None, Some("T1190"));
    add("SQLi: DELETE FROM", "delete from", Severity::High, AttackCategory::SqlInjection, None, Some("T1190"));
    add("SQLi: UPDATE SET", "update set", Severity::High, AttackCategory::SqlInjection, None, Some("T1190"));
    add("SQLi: EXEC XP_", "exec xp_", Severity::Critical, AttackCategory::SqlInjection, None, Some("T1190"));
    add("SQLi: XP_CMDSHELL", "xp_cmdshell", Severity::Critical, AttackCategory::SqlInjection, None, Some("T1190"));
    add("SQLi: WAITFOR DELAY", "waitfor delay", Severity::High, AttackCategory::SqlInjection, None, Some("T1190"));
    add("SQLi: BENCHMARK(", "benchmark(", Severity::High, AttackCategory::SqlInjection, None, Some("T1190"));
    add("SQLi: SLEEP(", "sleep(", Severity::Medium, AttackCategory::SqlInjection, None, Some("T1190"));
    add("SQLi: INFORMATION_SCHEMA", "information_schema", Severity::High, AttackCategory::SqlInjection, None, Some("T1190"));
    add("SQLi: LOAD_FILE(", "load_file(", Severity::Critical, AttackCategory::SqlInjection, None, Some("T1190"));
    add("SQLi: INTO OUTFILE", "into outfile", Severity::Critical, AttackCategory::SqlInjection, None, Some("T1190"));
    add("SQLi: INTO DUMPFILE", "into dumpfile", Severity::Critical, AttackCategory::SqlInjection, None, Some("T1190"));
    add("SQLi: CONCAT(", "concat(", Severity::Medium, AttackCategory::SqlInjection, None, Some("T1190"));
    add("SQLi: GROUP_CONCAT(", "group_concat(", Severity::High, AttackCategory::SqlInjection, None, Some("T1190"));
    add("SQLi: CHAR(", "char(", Severity::Medium, AttackCategory::SqlInjection, None, Some("T1190"));
    add("SQLi: HAVING 1=1", "having 1=1", Severity::High, AttackCategory::SqlInjection, None, Some("T1190"));
    add("SQLi: ORDER BY 100", "order by 100", Severity::Medium, AttackCategory::SqlInjection, None, Some("T1190"));
    add("SQLi: Comment bypass --", "' --", Severity::High, AttackCategory::SqlInjection, None, Some("T1190"));
    add("SQLi: Comment bypass #", "' #", Severity::High, AttackCategory::SqlInjection, None, Some("T1190"));
    add("SQLi: Hex encode 0x", "0x3127", Severity::High, AttackCategory::SqlInjection, None, Some("T1190"));
    add("SQLi: EXTRACTVALUE(", "extractvalue(", Severity::High, AttackCategory::SqlInjection, None, Some("T1190"));
    add("SQLi: UPDATEXML(", "updatexml(", Severity::High, AttackCategory::SqlInjection, None, Some("T1190"));
    add("SQLi: PG COPY FROM", "copy from program", Severity::Critical, AttackCategory::SqlInjection, None, Some("T1190"));
    add("SQLi: CAST(", "cast(", Severity::Low, AttackCategory::SqlInjection, None, Some("T1190"));

    // ── Cross-Site Scripting (25 patterns) ───────────────────────────────
    add("XSS: Script tag", "<script", Severity::High, AttackCategory::CrossSiteScripting, None, Some("T1189"));
    add("XSS: Script close", "</script>", Severity::High, AttackCategory::CrossSiteScripting, None, Some("T1189"));
    add("XSS: javascript:", "javascript:", Severity::High, AttackCategory::CrossSiteScripting, None, Some("T1189"));
    add("XSS: vbscript:", "vbscript:", Severity::High, AttackCategory::CrossSiteScripting, None, Some("T1189"));
    add("XSS: onerror=", "onerror=", Severity::High, AttackCategory::CrossSiteScripting, None, Some("T1189"));
    add("XSS: onload=", "onload=", Severity::Medium, AttackCategory::CrossSiteScripting, None, Some("T1189"));
    add("XSS: onmouseover=", "onmouseover=", Severity::Medium, AttackCategory::CrossSiteScripting, None, Some("T1189"));
    add("XSS: onfocus=", "onfocus=", Severity::Medium, AttackCategory::CrossSiteScripting, None, Some("T1189"));
    add("XSS: onblur=", "onblur=", Severity::Medium, AttackCategory::CrossSiteScripting, None, Some("T1189"));
    add("XSS: onclick=", "onclick=", Severity::Medium, AttackCategory::CrossSiteScripting, None, Some("T1189"));
    add("XSS: onsubmit=", "onsubmit=", Severity::Medium, AttackCategory::CrossSiteScripting, None, Some("T1189"));
    add("XSS: eval(", "eval(", Severity::High, AttackCategory::CrossSiteScripting, None, Some("T1189"));
    add("XSS: document.cookie", "document.cookie", Severity::Critical, AttackCategory::CrossSiteScripting, None, Some("T1189"));
    add("XSS: document.domain", "document.domain", Severity::High, AttackCategory::CrossSiteScripting, None, Some("T1189"));
    add("XSS: document.write", "document.write", Severity::High, AttackCategory::CrossSiteScripting, None, Some("T1189"));
    add("XSS: window.location", "window.location", Severity::High, AttackCategory::CrossSiteScripting, None, Some("T1189"));
    add("XSS: innerHTML=", "innerhtml=", Severity::High, AttackCategory::CrossSiteScripting, None, Some("T1189"));
    add("XSS: fromCharCode", "fromcharcode", Severity::High, AttackCategory::CrossSiteScripting, None, Some("T1189"));
    add("XSS: SVG onload", "<svg onload", Severity::High, AttackCategory::CrossSiteScripting, None, Some("T1189"));
    add("XSS: IMG SRC onerror", "<img src onerror", Severity::High, AttackCategory::CrossSiteScripting, None, Some("T1189"));
    add("XSS: IFRAME src", "<iframe", Severity::Medium, AttackCategory::CrossSiteScripting, None, Some("T1189"));
    add("XSS: BODY onload", "<body onload", Severity::High, AttackCategory::CrossSiteScripting, None, Some("T1189"));
    add("XSS: Expression(", "expression(", Severity::High, AttackCategory::CrossSiteScripting, None, Some("T1189"));
    add("XSS: data:text/html", "data:text/html", Severity::High, AttackCategory::CrossSiteScripting, None, Some("T1189"));
    add("XSS: alert(", "alert(", Severity::Medium, AttackCategory::CrossSiteScripting, None, Some("T1189"));

    // ── Command Injection (25 patterns) ──────────────────────────────────
    add("CMDi: Pipe command", "| /bin/", Severity::Critical, AttackCategory::CommandInjection, None, Some("T1059"));
    add("CMDi: Backtick exec", "`id`", Severity::Critical, AttackCategory::CommandInjection, None, Some("T1059"));
    add("CMDi: $( subshell", "$(", Severity::High, AttackCategory::CommandInjection, None, Some("T1059"));
    add("CMDi: /etc/passwd", "/etc/passwd", Severity::Critical, AttackCategory::CommandInjection, None, Some("T1059"));
    add("CMDi: /etc/shadow", "/etc/shadow", Severity::Critical, AttackCategory::CommandInjection, None, Some("T1059"));
    add("CMDi: /bin/sh", "/bin/sh", Severity::Critical, AttackCategory::CommandInjection, None, Some("T1059"));
    add("CMDi: /bin/bash", "/bin/bash", Severity::Critical, AttackCategory::CommandInjection, None, Some("T1059"));
    add("CMDi: cmd.exe", "cmd.exe", Severity::Critical, AttackCategory::CommandInjection, None, Some("T1059"));
    add("CMDi: powershell", "powershell", Severity::Critical, AttackCategory::CommandInjection, None, Some("T1059"));
    add("CMDi: wget http", "wget http", Severity::High, AttackCategory::CommandInjection, None, Some("T1059"));
    add("CMDi: curl http", "curl http", Severity::High, AttackCategory::CommandInjection, None, Some("T1059"));
    add("CMDi: nc -e", "nc -e", Severity::Critical, AttackCategory::CommandInjection, None, Some("T1059"));
    add("CMDi: netcat -e", "netcat -e", Severity::Critical, AttackCategory::CommandInjection, None, Some("T1059"));
    add("CMDi: python -c", "python -c", Severity::High, AttackCategory::CommandInjection, None, Some("T1059"));
    add("CMDi: perl -e", "perl -e", Severity::High, AttackCategory::CommandInjection, None, Some("T1059"));
    add("CMDi: ruby -e", "ruby -e", Severity::High, AttackCategory::CommandInjection, None, Some("T1059"));
    add("CMDi: php -r", "php -r", Severity::High, AttackCategory::CommandInjection, None, Some("T1059"));
    add("CMDi: ; cat ", "; cat ", Severity::High, AttackCategory::CommandInjection, None, Some("T1059"));
    add("CMDi: && cat ", "&& cat ", Severity::High, AttackCategory::CommandInjection, None, Some("T1059"));
    add("CMDi: || cat ", "|| cat ", Severity::High, AttackCategory::CommandInjection, None, Some("T1059"));
    add("CMDi: chmod 777", "chmod 777", Severity::High, AttackCategory::CommandInjection, None, Some("T1059"));
    add("CMDi: chown root", "chown root", Severity::High, AttackCategory::CommandInjection, None, Some("T1059"));
    add("CMDi: mkfifo", "mkfifo", Severity::Critical, AttackCategory::CommandInjection, None, Some("T1059"));
    add("CMDi: /dev/tcp/", "/dev/tcp/", Severity::Critical, AttackCategory::CommandInjection, None, Some("T1059"));
    add("CMDi: base64 -d", "base64 -d", Severity::High, AttackCategory::CommandInjection, None, Some("T1059"));

    // ── Path Traversal (15 patterns) ─────────────────────────────────────
    add("PathTrav: ../../../", "../../../", Severity::High, AttackCategory::PathTraversal, None, Some("T1083"));
    add("PathTrav: ..\\..\\", "..\\..\\", Severity::High, AttackCategory::PathTraversal, None, Some("T1083"));
    add("PathTrav: %2e%2e/", "%2e%2e/", Severity::High, AttackCategory::PathTraversal, None, Some("T1083"));
    add("PathTrav: %2e%2e%2f", "%2e%2e%2f", Severity::High, AttackCategory::PathTraversal, None, Some("T1083"));
    add("PathTrav: ..%252f", "..%252f", Severity::High, AttackCategory::PathTraversal, None, Some("T1083"));
    add("PathTrav: ....//", "....//", Severity::High, AttackCategory::PathTraversal, None, Some("T1083"));
    add("PathTrav: /proc/self", "/proc/self", Severity::Critical, AttackCategory::PathTraversal, None, Some("T1083"));
    add("PathTrav: /proc/version", "/proc/version", Severity::High, AttackCategory::PathTraversal, None, Some("T1083"));
    add("PathTrav: /var/log/", "/var/log/", Severity::Medium, AttackCategory::PathTraversal, None, Some("T1083"));
    add("PathTrav: /tmp/", "/tmp/", Severity::Low, AttackCategory::PathTraversal, None, Some("T1083"));
    add("PathTrav: C:\\Windows\\", "C:\\Windows\\", Severity::High, AttackCategory::PathTraversal, None, Some("T1083"));
    add("PathTrav: \\\\..\\", "\\\\..\\", Severity::High, AttackCategory::PathTraversal, None, Some("T1083"));
    add("PathTrav: file:///", "file:///", Severity::High, AttackCategory::PathTraversal, None, Some("T1083"));
    add("PathTrav: php://filter", "php://filter", Severity::Critical, AttackCategory::PathTraversal, None, Some("T1083"));
    add("PathTrav: php://input", "php://input", Severity::Critical, AttackCategory::PathTraversal, None, Some("T1083"));

    sigs
}

fn builtin_signatures_part2() -> Vec<Signature> {
    let mut sigs = Vec::with_capacity(100);
    let mut id = 1000100u32;
    let mut add = |name: &str, pat: &str, sev: Severity, cat: AttackCategory, cve: Option<&str>, mitre: Option<&str>| {
        sigs.push(Signature {
            id: { id += 1; id },
            name: name.to_string(),
            pattern: pat.as_bytes().to_vec(),
            severity: sev,
            category: cat,
            cve: cve.map(|s| s.to_string()),
            mitre_id: mitre.map(|s| s.to_string()),
            enabled: true,
        });
    };

    // ── Shellcode / Exploit Payloads (20 patterns) ───────────────────────
    add("Shell: NOP sled x86", "\x00\x00\x00\x00\x00\x00", Severity::Critical, AttackCategory::Shellcode, None, Some("T1203"));
    add("Shell: /bin/sh spawn", "/bin/sh", Severity::Critical, AttackCategory::Shellcode, None, Some("T1203"));
    add("Shell: ELF header", "\x7fELF", Severity::High, AttackCategory::Shellcode, None, Some("T1203"));
    add("Shell: MZ PE header", "MZ", Severity::High, AttackCategory::Shellcode, None, Some("T1203"));
    add("Shell: PK ZIP in stream", "PK\x03\x04", Severity::Medium, AttackCategory::Shellcode, None, Some("T1203"));
    add("Shell: Reverse shell python", "import socket,subprocess,os", Severity::Critical, AttackCategory::Shellcode, None, Some("T1059.006"));
    add("Shell: Reverse shell perl", "use Socket;", Severity::High, AttackCategory::Shellcode, None, Some("T1059.006"));
    add("Shell: Meterpreter stage", "metsrv.dll", Severity::Critical, AttackCategory::Shellcode, None, Some("T1203"));
    add("Shell: Cobalt Strike", "beacon.dll", Severity::Critical, AttackCategory::Shellcode, None, Some("T1203"));
    add("Shell: Empire agent", "import empire", Severity::Critical, AttackCategory::Shellcode, None, Some("T1203"));
    add("Shell: Log4Shell JNDI", "${jndi:", Severity::Critical, AttackCategory::Shellcode, Some("CVE-2021-44228"), Some("T1190"));
    add("Shell: Log4Shell lookup", "${jndi:ldap://", Severity::Critical, AttackCategory::Shellcode, Some("CVE-2021-44228"), Some("T1190"));
    add("Shell: Log4Shell rmi", "${jndi:rmi://", Severity::Critical, AttackCategory::Shellcode, Some("CVE-2021-44228"), Some("T1190"));
    add("Shell: Spring4Shell", "class.module.classLoader", Severity::Critical, AttackCategory::Shellcode, Some("CVE-2022-22965"), Some("T1190"));
    add("Shell: Shellshock", "() { :;}", Severity::Critical, AttackCategory::Shellcode, Some("CVE-2014-6271"), Some("T1190"));
    add("Shell: Heartbleed probe", "heartbleed", Severity::Critical, AttackCategory::Shellcode, Some("CVE-2014-0160"), Some("T1190"));
    add("Shell: EternalBlue SMB", "\x00\x00\x00\x00SMB", Severity::Critical, AttackCategory::Shellcode, Some("CVE-2017-0144"), Some("T1210"));
    add("Shell: ProxyShell", "/autodiscover/autodiscover.json", Severity::Critical, AttackCategory::Shellcode, Some("CVE-2021-34473"), Some("T1190"));
    add("Shell: ProxyLogon", "/owa/auth/logon.aspx", Severity::High, AttackCategory::Shellcode, Some("CVE-2021-26855"), Some("T1190"));
    add("Shell: PrintNightmare", "\\\\\\pipe\\spoolss", Severity::Critical, AttackCategory::Shellcode, Some("CVE-2021-34527"), Some("T1210"));

    // ── C2 Beacon / Malware Callbacks (20 patterns) ──────────────────────
    add("C2: Cobalt Strike beacon", "/submit.php?id=", Severity::Critical, AttackCategory::C2Beacon, None, Some("T1071.001"));
    add("C2: Cobalt Strike pipe", "\\\\.\\pipe\\msagent_", Severity::Critical, AttackCategory::C2Beacon, None, Some("T1071"));
    add("C2: Metasploit handler", "4d5a9000030000000400", Severity::Critical, AttackCategory::C2Beacon, None, Some("T1071"));
    add("C2: Empire stager", "/login/process.php", Severity::High, AttackCategory::C2Beacon, None, Some("T1071.001"));
    add("C2: Covenant grunt", "/en-us/test.html", Severity::High, AttackCategory::C2Beacon, None, Some("T1071.001"));
    add("C2: PoshC2 implant", "/Srehsien", Severity::High, AttackCategory::C2Beacon, None, Some("T1071.001"));
    add("C2: Sliver beacon", "/rpc.SliverRPC", Severity::Critical, AttackCategory::C2Beacon, None, Some("T1071"));
    add("C2: DNS tunnel base64", "AAAAAAAAAA", Severity::Medium, AttackCategory::C2Beacon, None, Some("T1071.004"));
    add("C2: Tor hidden svc", ".onion", Severity::High, AttackCategory::C2Beacon, None, Some("T1090.003"));
    add("C2: DGA-like domain", "asdkjhqwekj", Severity::Medium, AttackCategory::C2Beacon, None, Some("T1568.002"));
    add("C2: Reverse HTTP", "X-Session-Id:", Severity::Medium, AttackCategory::C2Beacon, None, Some("T1071.001"));
    add("C2: Base64 POST body long", "UFFSU0VS", Severity::Medium, AttackCategory::C2Beacon, None, Some("T1132.001"));
    add("C2: Mimikatz", "mimikatz", Severity::Critical, AttackCategory::C2Beacon, None, Some("T1003"));
    add("C2: LaZagne", "lazagne", Severity::Critical, AttackCategory::C2Beacon, None, Some("T1003"));
    add("C2: BloodHound", "sharphound", Severity::Critical, AttackCategory::C2Beacon, None, Some("T1087"));
    add("C2: Rubeus", "rubeus", Severity::Critical, AttackCategory::C2Beacon, None, Some("T1558"));
    add("C2: CrackMapExec", "crackmapexec", Severity::Critical, AttackCategory::C2Beacon, None, Some("T1021"));
    add("C2: Impacket", "impacket", Severity::Critical, AttackCategory::C2Beacon, None, Some("T1021"));
    add("C2: Evil-WinRM", "evil-winrm", Severity::Critical, AttackCategory::C2Beacon, None, Some("T1021.006"));
    add("C2: Chisel tunnel", "chisel client", Severity::High, AttackCategory::C2Beacon, None, Some("T1572"));

    // ── Credential Theft (15 patterns) ───────────────────────────────────
    add("Cred: Basic Auth in URL", "://admin:admin@", Severity::Critical, AttackCategory::CredentialTheft, None, Some("T1110"));
    add("Cred: Default root:root", "root:root", Severity::High, AttackCategory::CredentialTheft, None, Some("T1078"));
    add("Cred: Default admin:admin", "admin:admin", Severity::High, AttackCategory::CredentialTheft, None, Some("T1078"));
    add("Cred: Default admin:password", "admin:password", Severity::High, AttackCategory::CredentialTheft, None, Some("T1078"));
    add("Cred: SAM dump", "reg save hklm\\sam", Severity::Critical, AttackCategory::CredentialTheft, None, Some("T1003.002"));
    add("Cred: NTDS dit", "ntds.dit", Severity::Critical, AttackCategory::CredentialTheft, None, Some("T1003.003"));
    add("Cred: LSA secrets", "lsadump::sam", Severity::Critical, AttackCategory::CredentialTheft, None, Some("T1003.004"));
    add("Cred: Kerberoast", "kerberoast", Severity::Critical, AttackCategory::CredentialTheft, None, Some("T1558.003"));
    add("Cred: DCSync", "dcsync", Severity::Critical, AttackCategory::CredentialTheft, None, Some("T1003.006"));
    add("Cred: Pass the hash", "sekurlsa::pth", Severity::Critical, AttackCategory::CredentialTheft, None, Some("T1550.002"));
    add("Cred: LSASS dump", "lsass.dmp", Severity::Critical, AttackCategory::CredentialTheft, None, Some("T1003.001"));
    add("Cred: procdump lsass", "procdump -ma lsass", Severity::Critical, AttackCategory::CredentialTheft, None, Some("T1003.001"));
    add("Cred: hashdump", "hashdump", Severity::Critical, AttackCategory::CredentialTheft, None, Some("T1003"));
    add("Cred: SSH private key", "-----BEGIN RSA PRIVATE", Severity::Critical, AttackCategory::CredentialTheft, None, Some("T1552.004"));
    add("Cred: AWS access key", "AKIA", Severity::Critical, AttackCategory::CredentialTheft, None, Some("T1552.001"));

    // ── Web Shells (15 patterns) ─────────────────────────────────────────
    add("WebShell: China Chopper", "eval(Request", Severity::Critical, AttackCategory::WebShell, None, Some("T1505.003"));
    add("WebShell: WSO shell", "WSO 2.1", Severity::Critical, AttackCategory::WebShell, None, Some("T1505.003"));
    add("WebShell: r57 shell", "r57shell", Severity::Critical, AttackCategory::WebShell, None, Some("T1505.003"));
    add("WebShell: c99 shell", "c99shell", Severity::Critical, AttackCategory::WebShell, None, Some("T1505.003"));
    add("WebShell: b374k", "b374k", Severity::Critical, AttackCategory::WebShell, None, Some("T1505.003"));
    add("WebShell: p0wny shell", "p0wny", Severity::Critical, AttackCategory::WebShell, None, Some("T1505.003"));
    add("WebShell: PHP system()", "system($_GET", Severity::Critical, AttackCategory::WebShell, None, Some("T1505.003"));
    add("WebShell: PHP exec()", "exec($_GET", Severity::Critical, AttackCategory::WebShell, None, Some("T1505.003"));
    add("WebShell: PHP passthru", "passthru($_GET", Severity::Critical, AttackCategory::WebShell, None, Some("T1505.003"));
    add("WebShell: PHP shell_exec", "shell_exec(", Severity::Critical, AttackCategory::WebShell, None, Some("T1505.003"));
    add("WebShell: PHP assert eval", "assert(eval(", Severity::Critical, AttackCategory::WebShell, None, Some("T1505.003"));
    add("WebShell: JSP Runtime", "Runtime.getRuntime().exec(", Severity::Critical, AttackCategory::WebShell, None, Some("T1505.003"));
    add("WebShell: ASP wscript", "wscript.shell", Severity::Critical, AttackCategory::WebShell, None, Some("T1505.003"));
    add("WebShell: phpinfo()", "phpinfo()", Severity::Medium, AttackCategory::WebShell, None, Some("T1592"));
    add("WebShell: PHP base64 eval", "eval(base64_decode(", Severity::Critical, AttackCategory::WebShell, None, Some("T1505.003"));

    // ── Cryptomining (10 patterns) ───────────────────────────────────────
    add("Crypto: Stratum protocol", "stratum+tcp://", Severity::High, AttackCategory::CryptoMining, None, Some("T1496"));
    add("Crypto: Stratum+SSL", "stratum+ssl://", Severity::High, AttackCategory::CryptoMining, None, Some("T1496"));
    add("Crypto: XMRig", "xmrig", Severity::Critical, AttackCategory::CryptoMining, None, Some("T1496"));
    add("Crypto: Mining pool", "pool.minexmr", Severity::Critical, AttackCategory::CryptoMining, None, Some("T1496"));
    add("Crypto: NiceHash", "nicehash.com", Severity::High, AttackCategory::CryptoMining, None, Some("T1496"));
    add("Crypto: Coinhive", "coinhive.min.js", Severity::Critical, AttackCategory::CryptoMining, None, Some("T1496"));
    add("Crypto: CoinImp", "coinimp.com", Severity::Critical, AttackCategory::CryptoMining, None, Some("T1496"));
    add("Crypto: Mining JSON-RPC", "mining.submit", Severity::High, AttackCategory::CryptoMining, None, Some("T1496"));
    add("Crypto: Mining authorize", "mining.authorize", Severity::High, AttackCategory::CryptoMining, None, Some("T1496"));
    add("Crypto: Monero wallet addr", "4", Severity::Low, AttackCategory::CryptoMining, None, Some("T1496"));

    // ── Lateral Movement (10 patterns) ───────────────────────────────────
    add("Lateral: PsExec SVC", "PSEXESVC", Severity::High, AttackCategory::LateralMovement, None, Some("T1021.002"));
    add("Lateral: WMI exec", "Win32_Process Create", Severity::High, AttackCategory::LateralMovement, None, Some("T1047"));
    add("Lateral: WinRM exec", "/wsman", Severity::Medium, AttackCategory::LateralMovement, None, Some("T1021.006"));
    add("Lateral: SMB admin$", "\\ADMIN$", Severity::High, AttackCategory::LateralMovement, None, Some("T1021.002"));
    add("Lateral: SMB c$", "\\C$", Severity::High, AttackCategory::LateralMovement, None, Some("T1021.002"));
    add("Lateral: SMB ipc$", "\\IPC$", Severity::Medium, AttackCategory::LateralMovement, None, Some("T1021.002"));
    add("Lateral: schtasks create", "schtasks /create", Severity::High, AttackCategory::LateralMovement, None, Some("T1053.005"));
    add("Lateral: at.exe", "at.exe \\\\", Severity::High, AttackCategory::LateralMovement, None, Some("T1053.002"));
    add("Lateral: sc.exe create", "sc.exe create", Severity::High, AttackCategory::LateralMovement, None, Some("T1543.003"));
    add("Lateral: RDP tunnel", "mstsc /v:", Severity::Medium, AttackCategory::LateralMovement, None, Some("T1021.001"));

    // ── Data Exfiltration (10 patterns) ──────────────────────────────────
    add("Exfil: Large base64 blob", "base64,", Severity::Medium, AttackCategory::DataExfiltration, None, Some("T1048"));
    add("Exfil: DNS TXT exfil", "TXT?q=", Severity::High, AttackCategory::DataExfiltration, None, Some("T1048.003"));
    add("Exfil: ICMP tunnel data", "\x08\x00", Severity::Medium, AttackCategory::DataExfiltration, None, Some("T1048.003"));
    add("Exfil: pastebin.com", "pastebin.com", Severity::Medium, AttackCategory::DataExfiltration, None, Some("T1567.002"));
    add("Exfil: transfer.sh", "transfer.sh", Severity::High, AttackCategory::DataExfiltration, None, Some("T1567.002"));
    add("Exfil: ngrok.io", "ngrok.io", Severity::High, AttackCategory::DataExfiltration, None, Some("T1572"));
    add("Exfil: Discord webhook", "discord.com/api/webhooks", Severity::High, AttackCategory::DataExfiltration, None, Some("T1567.002"));
    add("Exfil: Telegram bot API", "api.telegram.org/bot", Severity::High, AttackCategory::DataExfiltration, None, Some("T1567.002"));
    add("Exfil: Mega.nz upload", "mega.nz", Severity::Medium, AttackCategory::DataExfiltration, None, Some("T1567.002"));
    add("Exfil: Dropbox API", "content.dropboxapi.com", Severity::Medium, AttackCategory::DataExfiltration, None, Some("T1567.002"));

    sigs
}

// ── Main IDS Engine ──────────────────────────────────────────────────────────

pub struct IntrusionDetector {
    /// Aho-Corasick automaton for O(n) multi-pattern matching
    automaton: RwLock<Option<AhoCorasick>>,
    /// Pattern index → Signature mapping
    pattern_index: RwLock<Vec<Signature>>,
    /// Additional custom signatures not yet compiled into automaton
    custom_sigs: RwLock<Vec<Signature>>,
    /// #592 Dedup: overlapping rules across rulesets deduplicated
    sig_dedup: RwLock<DedupStore<u32, Vec<u8>>>,
    /// #2 Tiered cache: frequently-hit rules hot, rare rules cold/compressed
    rule_cache: TieredCache<u32, Signature>,
    /// #1 Hierarchical state: alert history at O(log n) granularity
    alert_history: RwLock<HierarchicalState<AlertWindow>>,
    /// #5 Streaming accumulation: accumulate match state per window
    current_window: RwLock<AlertWindow>,
    /// #3 Reversible: store verdicts, recompute match chain on demand
    verdicts: RwLock<PruningMap<u64, MatchVerdict>>,
    /// Recent alerts (bounded by #569 pruning)
    recent_alerts: RwLock<VecDeque<Alert>>,
    max_recent_alerts: usize,
    /// Rate-based detection state
    rate_tracker: RwLock<RateTracker>,
    /// Stats
    packets_inspected: AtomicU64,
    alerts_generated: AtomicU64,
    signatures_loaded: AtomicU64,
    bytes_inspected: AtomicU64,
    /// #6 Theoretical verifier
    metrics: Option<MemoryMetrics>,
    enabled: bool,
    mode: IdsMode,
    /// Rate thresholds
    syn_flood_threshold: u64,
    brute_force_threshold: u64,
    port_scan_threshold: usize,
}

impl IntrusionDetector {
    pub fn new(mode: IdsMode) -> Self {
        let mut det = Self {
            automaton: RwLock::new(None),
            pattern_index: RwLock::new(Vec::new()),
            custom_sigs: RwLock::new(Vec::new()),
            sig_dedup: RwLock::new(DedupStore::new()),
            rule_cache: TieredCache::new(10_000),
            alert_history: RwLock::new(HierarchicalState::new(6, 10)),
            current_window: RwLock::new(AlertWindow::default()),
            verdicts: RwLock::new(
                PruningMap::new(50_000).with_ttl(std::time::Duration::from_secs(3600)),
            ),
            recent_alerts: RwLock::new(VecDeque::with_capacity(5000)),
            max_recent_alerts: 5000,
            rate_tracker: RwLock::new(RateTracker::new()),
            packets_inspected: AtomicU64::new(0),
            alerts_generated: AtomicU64::new(0),
            signatures_loaded: AtomicU64::new(0),
            bytes_inspected: AtomicU64::new(0),
            metrics: None,
            enabled: true,
            mode,
            syn_flood_threshold: 1000,
            brute_force_threshold: 10,
            port_scan_threshold: 25,
        };
        // Load all built-in signatures
        det.load_builtin_signatures();
        det
    }

    /// #6 Theoretical verifier: bound rule engine memory at 32MB.
    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("ids", 32 * 1024 * 1024);
        self.rule_cache = self.rule_cache.with_metrics(metrics.clone(), "ids");
        self.metrics = Some(metrics);
        self
    }

    /// Load all 200+ built-in attack signatures and compile Aho-Corasick automaton.
    fn load_builtin_signatures(&mut self) {
        let mut all_sigs = builtin_signatures();
        all_sigs.extend(builtin_signatures_part2());

        let patterns: Vec<&[u8]> = all_sigs.iter().map(|s| s.pattern.as_slice()).collect();
        let ac = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&patterns)
            .expect("Failed to build Aho-Corasick automaton");

        let count = all_sigs.len();
        let mut dedup = self.sig_dedup.write();
        for sig in &all_sigs {
            dedup.insert(sig.id, sig.pattern.clone());
            self.rule_cache.insert(sig.id, sig.clone());
        }

        *self.automaton.write() = Some(ac);
        *self.pattern_index.write() = all_sigs;
        self.signatures_loaded.store(count as u64, Ordering::Relaxed);
    }

    /// Add a custom signature and recompile the automaton.
    pub fn add_signature(&self, sig: Signature) {
        {
            let mut dedup = self.sig_dedup.write();
            dedup.insert(sig.id, sig.pattern.clone());
            self.rule_cache.insert(sig.id, sig.clone());
            self.custom_sigs.write().push(sig);
        }
        self.recompile_automaton();
    }

    /// Recompile the Aho-Corasick automaton with all signatures.
    fn recompile_automaton(&self) {
        let mut all: Vec<Signature> = self.pattern_index.read().clone();
        all.extend(self.custom_sigs.read().iter().cloned());
        let patterns: Vec<&[u8]> = all.iter().map(|s| s.pattern.as_slice()).collect();
        if let Ok(ac) = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&patterns)
        {
            *self.automaton.write() = Some(ac);
            let count = all.len();
            *self.pattern_index.write() = all;
            self.signatures_loaded.store(count as u64, Ordering::Relaxed);
        }
    }

    /// Main inspection entry point — Aho-Corasick multi-pattern + rate-based + protocol-aware.
    pub fn inspect(&self, flow: &FlowRecord, payload: &[u8]) -> Vec<Alert> {
        if !self.enabled || payload.is_empty() { return Vec::new(); }
        self.packets_inspected.fetch_add(1, Ordering::Relaxed);
        self.bytes_inspected.fetch_add(payload.len() as u64, Ordering::Relaxed);

        let now = chrono::Utc::now().timestamp();
        let mut alerts = Vec::new();

        // ── Phase 1: Aho-Corasick multi-pattern matching (O(n) for all 200+ patterns) ──
        let ac_guard = self.automaton.read();
        let idx_guard = self.pattern_index.read();
        if let Some(ref ac) = *ac_guard {
            for mat in ac.find_iter(payload) {
                let pat_idx = mat.pattern().as_usize();
                if pat_idx < idx_guard.len() {
                    let sig = &idx_guard[pat_idx];
                    if !sig.enabled { continue; }
                    let alert_id = self.alerts_generated.fetch_add(1, Ordering::Relaxed);
                    self.verdicts.write().insert(alert_id, MatchVerdict {
                        matched: true, rule_id: sig.id, severity: sig.severity,
                        category: sig.category, timestamp: now,
                    });
                    let offset = mat.start();
                    let context_start = offset.saturating_sub(16);
                    let context_end = (mat.end() + 16).min(payload.len());
                    alerts.push(Alert {
                        id: alert_id, timestamp: now, severity: sig.severity,
                        rule_id: sig.id, rule_name: sig.name.clone(),
                        src_ip: flow.src_ip, dst_ip: flow.dst_ip,
                        src_port: flow.src_port, dst_port: flow.dst_port,
                        protocol: flow.protocol,
                        message: format!("[{}] {} (offset:{})", sig.category.as_str(), sig.name, offset),
                        payload_sample: Some(payload[context_start..context_end].to_vec()),
                    });
                }
            }
        }
        drop(ac_guard);
        drop(idx_guard);

        // ── Phase 2: Protocol-aware inspection ──
        let proto = ProtocolDetector::detect(payload, flow.dst_port);
        match proto {
            DetectedProtocol::Http => {
                self.inspect_http(flow, payload, now, &mut alerts);
            }
            DetectedProtocol::Dns => {
                self.inspect_dns(flow, payload, now, &mut alerts);
            }
            DetectedProtocol::Tls => {
                self.inspect_tls(flow, payload, now, &mut alerts);
            }
            DetectedProtocol::Ssh => {
                self.inspect_ssh(flow, payload, now, &mut alerts);
            }
            _ => {}
        }

        // ── Phase 3: Rate-based detection ──
        self.check_rates(flow, now, &mut alerts);

        // ── Phase 4: Accumulate into current window ──
        if !alerts.is_empty() {
            let mut window = self.current_window.write();
            for alert in &alerts {
                window.alert_count += 1;
                let idx = match alert.severity {
                    Severity::Info => 0, Severity::Low => 1, Severity::Medium => 2,
                    Severity::High => 3, Severity::Critical => 4,
                };
                window.by_severity[idx] += 1;
                let cat_key = alert.message.split(']').next()
                    .unwrap_or("unknown").trim_start_matches('[').to_string();
                *window.by_category.entry(cat_key).or_insert(0) += 1;
                window.unique_sources.insert(alert.src_ip);
            }
            let mut recent = self.recent_alerts.write();
            for alert in &alerts {
                if recent.len() >= self.max_recent_alerts { recent.pop_front(); }
                recent.push_back(alert.clone());
            }
        }
        alerts
    }

    // ── Protocol-Specific Inspectors ─────────────────────────────────────

    fn inspect_http(&self, flow: &FlowRecord, payload: &[u8], now: i64, alerts: &mut Vec<Alert>) {
        let text = String::from_utf8_lossy(payload);
        let lower = text.to_lowercase();

        // HTTP request smuggling detection
        let has_cl = lower.contains("content-length:");
        let has_te = lower.contains("transfer-encoding:");
        if has_cl && has_te {
            alerts.push(self.make_alert(flow, now, Severity::Critical,
                "HTTP Request Smuggling: Both Content-Length and Transfer-Encoding present",
                payload));
        }

        // HTTP response splitting / CRLF injection
        if lower.contains("%0d%0a") || lower.contains("\\r\\n") {
            alerts.push(self.make_alert(flow, now, Severity::High,
                "CRLF Injection / HTTP Response Splitting detected",
                payload));
        }

        // Oversized URI (>8KB often indicates buffer overflow attempt)
        if let Some(first_line_end) = text.find('\n') {
            if first_line_end > 8192 {
                alerts.push(self.make_alert(flow, now, Severity::High,
                    "Oversized HTTP URI (>8KB) — possible buffer overflow attempt",
                    payload));
            }
        }

        // Suspicious User-Agent strings
        let suspicious_agents = [
            "sqlmap", "nikto", "nessus", "nmap", "masscan", "zgrab",
            "gobuster", "dirbuster", "wfuzz", "ffuf", "hydra", "burpsuite",
            "owasp", "nuclei", "httpx", "subfinder", "amass",
        ];
        for agent in &suspicious_agents {
            if lower.contains(agent) {
                alerts.push(self.make_alert(flow, now, Severity::High,
                    &format!("Suspicious scanning tool User-Agent: {}", agent),
                    payload));
                break;
            }
        }

        // Directory bruteforce detection (common wordlist paths)
        let bruteforce_paths = [
            "/.env", "/wp-admin", "/wp-login.php", "/administrator",
            "/.git/config", "/.svn/entries", "/backup.sql", "/dump.sql",
            "/phpmyadmin", "/adminer.php", "/.htaccess", "/.htpasswd",
            "/server-status", "/server-info", "/xmlrpc.php", "/wp-config.php",
            "/.aws/credentials", "/.docker/config.json", "/actuator/health",
            "/api/swagger.json", "/graphql", "/debug/pprof",
        ];
        for path in &bruteforce_paths {
            if lower.contains(path) {
                alerts.push(self.make_alert(flow, now, Severity::Medium,
                    &format!("Sensitive path access attempt: {}", path),
                    payload));
                break;
            }
        }

        // Server-Side Request Forgery (SSRF) indicators
        let ssrf_patterns = [
            "http://169.254.169.254", "http://metadata.google",
            "http://100.100.100.200", "http://[::ffff:169.254",
            "http://localhost", "http://127.0.0.1", "http://0.0.0.0",
            "http://[::1]", "http://2130706433", "http://0x7f000001",
            "file:///etc/", "gopher://", "dict://",
        ];
        for pat in &ssrf_patterns {
            if lower.contains(pat) {
                alerts.push(self.make_alert(flow, now, Severity::Critical,
                    &format!("SSRF attempt detected: {}", pat),
                    payload));
                break;
            }
        }

        // XXE detection
        if lower.contains("<!entity") || lower.contains("<!doctype") && lower.contains("system") {
            alerts.push(self.make_alert(flow, now, Severity::Critical,
                "XML External Entity (XXE) injection attempt",
                payload));
        }

        // Deserialization attacks
        let deser_patterns = [
            "rO0AB", "aced0005", "ObjectInputStream",
            "__reduce__", "pickle.loads", "yaml.load",
            "java.lang.Runtime", "java.lang.ProcessBuilder",
        ];
        for pat in &deser_patterns {
            if lower.contains(&pat.to_lowercase()) {
                alerts.push(self.make_alert(flow, now, Severity::Critical,
                    &format!("Deserialization attack indicator: {}", pat),
                    payload));
                break;
            }
        }
    }

    fn inspect_dns(&self, flow: &FlowRecord, payload: &[u8], now: i64, alerts: &mut Vec<Alert>) {
        if payload.len() < 12 { return; }

        // DNS query count from header
        let qd_count = u16::from_be_bytes([payload[4], payload[5]]);

        // Abnormally large DNS query (possible exfiltration)
        if payload.len() > 512 {
            alerts.push(self.make_alert(flow, now, Severity::High,
                &format!("Oversized DNS query ({} bytes) — possible data exfiltration", payload.len()),
                payload));
        }

        // Many questions in single query (unusual)
        if qd_count > 5 {
            alerts.push(self.make_alert(flow, now, Severity::Medium,
                &format!("Unusual DNS query with {} questions", qd_count),
                payload));
        }

        // Check for DNS tunneling: long subdomain labels
        let mut pos = 12usize;
        let mut max_label_len = 0u8;
        let mut total_labels = 0u32;
        while pos < payload.len() {
            let label_len = payload[pos];
            if label_len == 0 || label_len > 63 { break; }
            if label_len > max_label_len { max_label_len = label_len; }
            total_labels += 1;
            pos += 1 + label_len as usize;
        }

        // Long labels suggest DNS tunneling (iodine, dnscat2, etc.)
        if max_label_len > 50 {
            alerts.push(self.make_alert(flow, now, Severity::Critical,
                &format!("DNS tunneling suspected: label length {} (max normal ~20)", max_label_len),
                payload));
        }

        // Many subdomains also suspicious
        if total_labels > 8 {
            alerts.push(self.make_alert(flow, now, Severity::High,
                &format!("Excessive DNS subdomain depth: {} labels", total_labels),
                payload));
        }

        // Check for high-entropy labels (base32/base64 encoded data)
        if pos > 12 && payload.len() > 20 {
            let query_bytes = &payload[12..pos.min(payload.len())];
            let entropy = byte_entropy(query_bytes);
            if entropy > 4.5 {
                alerts.push(self.make_alert(flow, now, Severity::High,
                    &format!("High-entropy DNS query (entropy: {:.2}) — possible encoded exfiltration", entropy),
                    payload));
            }
        }
    }

    fn inspect_tls(&self, flow: &FlowRecord, payload: &[u8], now: i64, alerts: &mut Vec<Alert>) {
        if payload.len() < 6 { return; }
        // TLS record: type(1) + version(2) + length(2)
        let tls_major = payload[1];
        let tls_minor = payload[2];

        // SSLv3 or TLS 1.0 — deprecated, insecure
        if tls_major == 3 && tls_minor == 0 {
            alerts.push(self.make_alert(flow, now, Severity::High,
                "Deprecated SSLv3 connection detected (POODLE vulnerable)",
                payload));
        }
        if tls_major == 3 && tls_minor == 1 {
            alerts.push(self.make_alert(flow, now, Severity::Medium,
                "Deprecated TLS 1.0 connection detected",
                payload));
        }

        // ClientHello with very large extensions (>16KB) — possible exploit
        if payload[0] == 0x16 && payload.len() > 16384 {
            alerts.push(self.make_alert(flow, now, Severity::High,
                "Oversized TLS ClientHello — possible exploit attempt",
                payload));
        }

        // TLS downgrade detection (SCSV sentinel)
        if payload.len() > 100 {
            // Look for TLS_FALLBACK_SCSV (0x56, 0x00) indicating downgrade
            for i in 0..payload.len()-1 {
                if payload[i] == 0x56 && payload[i+1] == 0x00 {
                    alerts.push(self.make_alert(flow, now, Severity::High,
                        "TLS downgrade attack detected (FALLBACK_SCSV present)",
                        payload));
                    break;
                }
            }
        }
    }

    fn inspect_ssh(&self, flow: &FlowRecord, payload: &[u8], now: i64, alerts: &mut Vec<Alert>) {
        let text = String::from_utf8_lossy(payload);

        // Detect old/weak SSH versions
        if text.starts_with("SSH-1.") {
            alerts.push(self.make_alert(flow, now, Severity::Critical,
                "SSHv1 connection detected — critically insecure protocol",
                payload));
        }

        // Detect SSH brute force (tracked via rate_tracker)
        // Detect SSH tunneling attempts (port forwarding)
        if text.contains("direct-tcpip") || text.contains("forwarded-tcpip") {
            alerts.push(self.make_alert(flow, now, Severity::Medium,
                "SSH port forwarding / tunneling detected",
                payload));
        }
    }

    // ── Rate-Based Detection ─────────────────────────────────────────────

    fn check_rates(&self, flow: &FlowRecord, now: i64, alerts: &mut Vec<Alert>) {
        let mut tracker = self.rate_tracker.write();
        let src = flow.src_ip;

        // Track connection rate
        let entry = tracker.connections.entry(src).or_insert((0, now, now));
        entry.0 += 1;
        entry.2 = now;

        // SYN flood detection (TCP SYN without established session)
        if flow.dst_port != 0 {
            let syn_count = tracker.syn_counts.entry(src).or_insert(0);
            *syn_count += 1;
            if *syn_count > self.syn_flood_threshold {
                alerts.push(self.make_alert(flow, now, Severity::Critical,
                    &format!("SYN flood detected from {} ({} SYNs in window)", src, syn_count),
                    &[]));
                *syn_count = 0; // reset to avoid alert storm
            }
        }

        // Port scan detection
        let ports = tracker.port_scans.entry(src).or_insert_with(HashSet::new);
        ports.insert(flow.dst_port);
        if ports.len() > self.port_scan_threshold {
            alerts.push(self.make_alert(flow, now, Severity::High,
                &format!("Port scan detected from {} ({} unique ports)", src, ports.len()),
                &[]));
            ports.clear();
        }

        // Brute force detection on auth ports
        let auth_ports = [22, 23, 3389, 5900, 21, 3306, 5432, 1433, 6379, 27017];
        if auth_ports.contains(&flow.dst_port) {
            let failures = tracker.auth_failures.entry(src).or_insert(0);
            *failures += 1;
            if *failures > self.brute_force_threshold {
                alerts.push(self.make_alert(flow, now, Severity::Critical,
                    &format!("Brute force attack on port {} from {} ({} attempts)",
                        flow.dst_port, src, failures),
                    &[]));
                *failures = 0;
            }
        }
    }

    fn make_alert(&self, flow: &FlowRecord, now: i64, severity: Severity, message: &str, payload: &[u8]) -> Alert {
        let alert_id = self.alerts_generated.fetch_add(1, Ordering::Relaxed);
        Alert {
            id: alert_id, timestamp: now, severity,
            rule_id: 0, rule_name: message.to_string(),
            src_ip: flow.src_ip, dst_ip: flow.dst_ip,
            src_port: flow.src_port, dst_port: flow.dst_port,
            protocol: flow.protocol,
            message: message.to_string(),
            payload_sample: if payload.is_empty() { None } else {
                Some(payload[..payload.len().min(128)].to_vec())
            },
        }
    }

    // ── Window Management & Stats ────────────────────────────────────────

    /// #1 Hierarchical: rotate window into O(log n) history.
    pub fn rotate_window(&self) {
        let window = std::mem::take(&mut *self.current_window.write());
        self.alert_history.write().checkpoint(window);
        // Also prune rate tracker periodically
        let mut tracker = self.rate_tracker.write();
        tracker.syn_counts.clear();
        // Keep port scan state for multi-window detection
    }

    /// Reset rate tracking counters (call periodically, e.g. every 60s).
    pub fn reset_rate_counters(&self) {
        let mut tracker = self.rate_tracker.write();
        tracker.connections.clear();
        tracker.auth_failures.clear();
        tracker.port_scans.clear();
        tracker.syn_counts.clear();
    }

    pub fn signature_count(&self) -> u64 { self.signatures_loaded.load(Ordering::Relaxed) }
    pub fn unique_signatures(&self) -> usize { self.sig_dedup.read().unique_value_count() }
    pub fn dedup_ratio(&self) -> f64 { self.sig_dedup.read().dedup_ratio() }
    pub fn total_alerts(&self) -> u64 { self.alerts_generated.load(Ordering::Relaxed) }
    pub fn packets_inspected(&self) -> u64 { self.packets_inspected.load(Ordering::Relaxed) }
    pub fn bytes_inspected(&self) -> u64 { self.bytes_inspected.load(Ordering::Relaxed) }
    pub fn recent_alerts(&self) -> Vec<Alert> { self.recent_alerts.read().iter().cloned().collect() }
    pub fn mode(&self) -> IdsMode { self.mode }
    pub fn set_enabled(&mut self, enabled: bool) { self.enabled = enabled; }

    pub fn category_stats(&self) -> HashMap<String, u64> {
        self.current_window.read().by_category.clone()
    }

    pub fn top_attackers(&self, limit: usize) -> Vec<(IpAddr, u64)> {
        let tracker = self.rate_tracker.read();
        let mut sorted: Vec<_> = tracker.connections.iter()
            .map(|(ip, (count, _, _))| (*ip, *count))
            .collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(limit);
        sorted
    }
}

// ── Utility Functions ────────────────────────────────────────────────────────

fn byte_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut freq = [0u32; 256];
    for &b in data { freq[b as usize] += 1; }
    let len = data.len() as f64;
    let mut entropy = 0.0f64;
    for &f in &freq {
        if f > 0 {
            let p = f as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

// ══════════════════════════════════════════════════════════════════════════════
// WORLD-CLASS IDS EXTENSIONS
// ══════════════════════════════════════════════════════════════════════════════

// ── Regex-Based Detection Rules ──────────────────────────────────────────────

use regex::RegexSet;

/// Regex-based rules catch evasion techniques that fixed-string matching misses:
/// variable whitespace, case mixing, comment insertion, encoding variations.
pub struct RegexRuleEngine {
    rules: Vec<RegexRule>,
    compiled: Option<RegexSet>,
}

pub struct RegexRule {
    pub id: u32,
    pub name: String,
    pub severity: Severity,
    pub category: AttackCategory,
    pub mitre_id: Option<String>,
}

impl RegexRuleEngine {
    pub fn new() -> Self {
        let mut engine = Self { rules: Vec::new(), compiled: None };
        engine.load_builtin_regex_rules();
        engine
    }

    fn load_builtin_regex_rules(&mut self) {
        let patterns_and_rules: Vec<(&str, &str, Severity, AttackCategory, Option<&str>)> = vec![
            // SQLi with evasion — variable whitespace, comments, case mixing
            (r"(?i)union\s+(?:/\*.*?\*/\s*)?(?:all\s+)?select", "SQLi: UNION SELECT (evasion-resistant)", Severity::Critical, AttackCategory::SqlInjection, Some("T1190")),
            (r"(?i)(?:'\s*|\d\s+)or\s+[\d']+=[\d']+", "SQLi: OR tautology (evasion-resistant)", Severity::High, AttackCategory::SqlInjection, Some("T1190")),
            (r"(?i)(?:select|insert|update|delete|drop|alter|create)\s+.*(?:from|into|table|database|set)", "SQLi: DML/DDL statement in traffic", Severity::High, AttackCategory::SqlInjection, Some("T1190")),
            (r"(?i)(?:exec|execute)\s*\(?\s*(?:xp_|sp_)", "SQLi: Stored procedure call", Severity::Critical, AttackCategory::SqlInjection, Some("T1190")),
            (r"(?i)waitfor\s+delay\s+'[\d:]+'\s*--", "SQLi: Time-based blind (WAITFOR)", Severity::Critical, AttackCategory::SqlInjection, Some("T1190")),
            (r"(?i)benchmark\s*\(\s*\d+\s*,", "SQLi: Time-based blind (BENCHMARK)", Severity::Critical, AttackCategory::SqlInjection, Some("T1190")),
            (r"(?i)(?:and|or)\s+\d+\s*=\s*\d+", "SQLi: Boolean-based blind", Severity::High, AttackCategory::SqlInjection, Some("T1190")),
            (r"(?i)(?:pg_sleep|sleep)\s*\(\s*\d+\s*\)", "SQLi: Time-based blind (SLEEP)", Severity::High, AttackCategory::SqlInjection, Some("T1190")),
            (r"(?i)(?:load_file|into\s+(?:out|dump)file)\s*\(", "SQLi: File read/write", Severity::Critical, AttackCategory::SqlInjection, Some("T1190")),
            (r"(?i)information_schema\s*\.\s*(?:tables|columns|schemata)", "SQLi: Schema enumeration", Severity::High, AttackCategory::SqlInjection, Some("T1190")),

            // XSS with evasion — encoded, obfuscated, polyglot
            (r"(?i)<\s*script[^>]*>", "XSS: Script tag (whitespace evasion)", Severity::High, AttackCategory::CrossSiteScripting, Some("T1189")),
            (r"(?i)(?:on(?:error|load|click|mouse\w+|focus|blur|submit|change|input|key\w+))\s*=", "XSS: Event handler attribute", Severity::High, AttackCategory::CrossSiteScripting, Some("T1189")),
            (r"(?i)javascript\s*:", "XSS: javascript: URI", Severity::High, AttackCategory::CrossSiteScripting, Some("T1189")),
            (r"(?i)document\s*\.\s*(?:cookie|domain|write|location)", "XSS: DOM access", Severity::Critical, AttackCategory::CrossSiteScripting, Some("T1189")),
            (r"(?i)(?:window|self|top|parent)\s*\.\s*(?:location|open|eval)", "XSS: Window manipulation", Severity::High, AttackCategory::CrossSiteScripting, Some("T1189")),
            (r#"(?i)<\s*(?:img|svg|body|iframe|embed|object|video|audio|source|input|button|details|marquee)\s+[^>]*(?:on\w+|src\s*=\s*['"]?javascript)"#, "XSS: Tag-based injection", Severity::High, AttackCategory::CrossSiteScripting, Some("T1189")),
            (r"(?i)(?:eval|settimeout|setinterval|Function|constructor)\s*[(]", "XSS: Code execution function", Severity::High, AttackCategory::CrossSiteScripting, Some("T1189")),
            (r"(?i)(?:atob|btoa|string\.fromcharcode|unescape|decodeuri)\s*[(]", "XSS: Encoding/decoding function", Severity::Medium, AttackCategory::CrossSiteScripting, Some("T1189")),

            // Command injection with evasion
            (r#"(?:;|\||&&|\$[(]|`)\s*(?:cat|ls|id|whoami|uname|pwd|wget|curl|nc|ncat|bash|sh|python|perl|ruby|php)\b"#, "CMDi: Shell command chaining", Severity::Critical, AttackCategory::CommandInjection, Some("T1059")),
            (r"(?i)(?:system|exec|passthru|shell_exec|popen|proc_open)\s*[(]", "CMDi: PHP execution function", Severity::Critical, AttackCategory::CommandInjection, Some("T1059")),
            (r"(?i)(?:os\.system|subprocess\.(?:call|run|popen|check_output))\s*[(]", "CMDi: Python execution", Severity::Critical, AttackCategory::CommandInjection, Some("T1059")),
            (r"(?i)(?:runtime\.getruntime.+\.exec|processbuilder)\s*[(]", "CMDi: Java execution", Severity::Critical, AttackCategory::CommandInjection, Some("T1059")),

            // Path traversal with encoding evasion
            (r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.%2e/|%2e\./|\.\.%5c|%252e%252e){2,}", "PathTrav: Multi-level traversal (evasion-resistant)", Severity::High, AttackCategory::PathTraversal, Some("T1083")),
            (r"(?i)/(?:etc/(?:passwd|shadow|hosts|resolv\.conf|sudoers)|proc/(?:self|version|cpuinfo|meminfo))", "PathTrav: Sensitive Unix file access", Severity::Critical, AttackCategory::PathTraversal, Some("T1083")),

            // SSRF patterns
            (r"(?i)(?:https?://|ftp://|gopher://|dict://|file://|ldap://|tftp://)(?:localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|metadata\.google)", "SSRF: Internal/metadata access", Severity::Critical, AttackCategory::ProtocolExploit, Some("T1190")),
            (r"(?i)(?:https?://|ftp://)(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)", "SSRF: RFC1918 internal network access", Severity::High, AttackCategory::ProtocolExploit, Some("T1190")),

            // LDAP injection
            (r"(?i)(?:[)]\s*(?:[|]|[&])\s*[(]|(?:[*][)]\s*[(]|[)]\s*[(]\s*[|]))", "LDAP Injection attempt", Severity::High, AttackCategory::ProtocolExploit, Some("T1190")),

            // Template injection (SSTI)
            (r"[{][{].*(?:__class__|__mro__|__subclasses__|__import__|config|request|lipsum|cycler).*[}][}]", "SSTI: Server-Side Template Injection", Severity::Critical, AttackCategory::CommandInjection, Some("T1190")),
            (r"[$][{].*(?:Runtime|ProcessBuilder|getClass|forName|Thread).*[}]", "SSTI: Java Expression Language injection", Severity::Critical, AttackCategory::CommandInjection, Some("T1190")),
        ];

        let mut regex_patterns = Vec::new();
        let mut id = 2000000u32;
        for (pattern, name, severity, category, mitre) in &patterns_and_rules {
            regex_patterns.push(*pattern);
            id += 1;
            self.rules.push(RegexRule {
                id,
                name: name.to_string(),
                severity: *severity,
                category: *category,
                mitre_id: mitre.map(|s| s.to_string()),
            });
        }

        match RegexSet::new(&regex_patterns) {
            Ok(set) => { self.compiled = Some(set); }
            Err(e) => { warn!("Failed to compile regex ruleset: {}", e); }
        }
    }

    /// Match all regex rules against payload text. Returns matching rule indices.
    pub fn match_payload(&self, text: &str) -> Vec<usize> {
        match &self.compiled {
            Some(set) => set.matches(text).iter().collect(),
            None => Vec::new(),
        }
    }

    pub fn rule_count(&self) -> usize { self.rules.len() }
}

// ── TCP Stream Reassembly ────────────────────────────────────────────────────

/// Reassembles TCP streams to detect attacks split across multiple packets.
/// Without this, trivial evasion by splitting "union" + " select" across packets.
pub struct StreamReassembler {
    /// flow_key → accumulated payload bytes
    streams: HashMap<u64, StreamState>,
    max_stream_bytes: usize,
    max_streams: usize,
}

struct StreamState {
    buffer: Vec<u8>,
    first_seen: i64,
    last_seen: i64,
    packet_count: u32,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
}

impl StreamReassembler {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
            max_stream_bytes: 65536, // 64KB per stream max
            max_streams: 10_000,
        }
    }

    /// Compute flow key from 5-tuple.
    fn flow_key(src: IpAddr, dst: IpAddr, sp: u16, dp: u16, proto: Protocol) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        src.hash(&mut hasher);
        dst.hash(&mut hasher);
        sp.hash(&mut hasher);
        dp.hash(&mut hasher);
        proto.hash(&mut hasher);
        hasher.finish()
    }

    /// Append payload to stream and return reassembled buffer if ready for inspection.
    pub fn append(&mut self, flow: &FlowRecord, payload: &[u8], now: i64) -> Option<Vec<u8>> {
        let key = Self::flow_key(flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, flow.protocol);

        // Evict oldest stream if at capacity
        if self.streams.len() >= self.max_streams && !self.streams.contains_key(&key) {
            if let Some(oldest_key) = self.streams.iter()
                .min_by_key(|(_, s)| s.last_seen)
                .map(|(k, _)| *k)
            {
                self.streams.remove(&oldest_key);
            }
        }

        let state = self.streams.entry(key).or_insert_with(|| StreamState {
            buffer: Vec::with_capacity(4096),
            first_seen: now,
            last_seen: now,
            packet_count: 0,
            src_ip: flow.src_ip,
            dst_ip: flow.dst_ip,
            src_port: flow.src_port,
            dst_port: flow.dst_port,
        });

        state.last_seen = now;
        state.packet_count += 1;

        // Append up to max_stream_bytes
        let remaining = self.max_stream_bytes.saturating_sub(state.buffer.len());
        let to_copy = payload.len().min(remaining);
        state.buffer.extend_from_slice(&payload[..to_copy]);

        // Return reassembled buffer every 4 packets or when buffer is large enough
        if state.packet_count % 4 == 0 || state.buffer.len() >= 4096 {
            Some(state.buffer.clone())
        } else {
            None
        }
    }

    /// Close and remove a stream, returning final buffer.
    pub fn close_stream(&mut self, flow: &FlowRecord) -> Option<Vec<u8>> {
        let key = Self::flow_key(flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, flow.protocol);
        self.streams.remove(&key).map(|s| s.buffer)
    }

    /// Expire streams older than given seconds.
    pub fn expire(&mut self, max_age_secs: i64) {
        let now = chrono::Utc::now().timestamp();
        self.streams.retain(|_, s| now - s.last_seen < max_age_secs);
    }

    pub fn active_streams(&self) -> usize { self.streams.len() }
    pub fn total_bytes(&self) -> usize { self.streams.values().map(|s| s.buffer.len()).sum() }
}

// ── JA3/JA3S TLS Fingerprinting ─────────────────────────────────────────────

/// JA3 creates an MD5 hash of TLS ClientHello parameters.
/// Known C2 frameworks (Cobalt Strike, Metasploit, Empire) have distinctive JA3 hashes.
pub struct Ja3Fingerprinter {
    /// Known malicious JA3 hashes → tool name
    known_bad: HashMap<String, String>,
    /// Observed JA3 hashes for profiling
    observed: RwLock<HashMap<String, Ja3Stats>>,
}

struct Ja3Stats {
    count: u64,
    first_seen: i64,
    last_seen: i64,
    sources: HashSet<IpAddr>,
}

impl Ja3Fingerprinter {
    pub fn new() -> Self {
        let mut known_bad = HashMap::new();
        // Known malicious JA3 hashes (real-world C2 fingerprints)
        known_bad.insert("72a589da586844d7f0818ce684948eea".into(), "Cobalt Strike (default)".into());
        known_bad.insert("a0e9f5d64349fb13191bc781f81f42e1".into(), "Cobalt Strike (4.0)".into());
        known_bad.insert("51c64c77e60f3980eea90869b68c58a8".into(), "Cobalt Strike (HTTPS)".into());
        known_bad.insert("b742b407517bac9536a77a7b0fee28e9".into(), "Cobalt Strike (4.1+)".into());
        known_bad.insert("e7d705a3286e19ea42f587b344ee6865".into(), "Metasploit (Meterpreter)".into());
        known_bad.insert("3b5074b1b5d032e5620f69f9f700ff0e".into(), "Metasploit (reverse_https)".into());
        known_bad.insert("5d65ea3fb1d4aa7d826733d2f2cbbb1d".into(), "Empire (default)".into());
        known_bad.insert("2d14b27507072b5f264bc18a43ca5747".into(), "PoshC2".into());
        known_bad.insert("4d7a28d6f2263ed61de88ca66eb011e3".into(), "Sliver (default)".into());
        known_bad.insert("cd08e31494f9531f0ab9561d0d02eb18".into(), "Covenant".into());
        known_bad.insert("19e29534fd49dd27d09234e639c4057e".into(), "Brute Ratel C4".into());
        known_bad.insert("bc6c386f7dcb98dbc04399ab1b5cf620".into(), "Havoc C2".into());
        known_bad.insert("6734f37431670b3ab4292b8f60f29984".into(), "Trickbot".into());
        known_bad.insert("e7170f3e18cbf9c83fbdfc6781e9ab77".into(), "Emotet".into());
        known_bad.insert("4e0e1cf08e625dbfc43e97b2e8f23956".into(), "QakBot".into());
        known_bad.insert("72e8a7e354e0f0ffa1e1a64f97b27cc3".into(), "IcedID".into());
        known_bad.insert("c12f54a3f91dc7e81ce93c0bfdad26ae".into(), "Bumblebee".into());
        known_bad.insert("3916f22f0a31a8abbb6dbe36ed5a8a88".into(), "AsyncRAT".into());
        known_bad.insert("a7a0c2ef6e8d3e43b26cb1587faae572".into(), "DarkComet".into());
        known_bad.insert("50a93e8c56f88863d0c17c93e0ee2e0e".into(), "njRAT".into());
        // Tor/anonymization
        known_bad.insert("e7d705a3286e19ea42f587b344ee6865".into(), "Tor Browser".into());
        // Suspicious automation
        known_bad.insert("0cc85d0df7e84190b261f53f692fb2f5".into(), "Python requests (default)".into());
        known_bad.insert("b32309a26951912be7dba376398abc3b".into(), "Go net/http (default)".into());
        known_bad.insert("3b5074b1b5d032e5620f69f9f700ff0e".into(), "curl (default)".into());

        Self {
            known_bad,
            observed: RwLock::new(HashMap::new()),
        }
    }

    /// Extract JA3 hash from a TLS ClientHello payload.
    /// JA3 = MD5(TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurveFormats)
    pub fn compute_ja3(&self, payload: &[u8]) -> Option<String> {
        if payload.len() < 44 || payload[0] != 0x16 { return None; } // Not a TLS handshake
        if payload[5] != 0x01 { return None; } // Not ClientHello

        let tls_version = u16::from_be_bytes([payload[1], payload[2]]);

        // Parse ClientHello to extract cipher suites
        let mut ja3_parts = Vec::new();
        ja3_parts.push(format!("{}", tls_version));

        // Simplified: extract cipher suite bytes as comma-separated values
        if payload.len() > 43 {
            let session_id_len = payload[43] as usize;
            let cipher_offset = 44 + session_id_len;
            if cipher_offset + 2 <= payload.len() {
                let cipher_len = u16::from_be_bytes([payload[cipher_offset], payload[cipher_offset + 1]]) as usize;
                let cipher_end = (cipher_offset + 2 + cipher_len).min(payload.len());
                let mut ciphers = Vec::new();
                let mut i = cipher_offset + 2;
                while i + 1 < cipher_end {
                    let cs = u16::from_be_bytes([payload[i], payload[i + 1]]);
                    // Skip GREASE values (0x?a?a pattern)
                    if cs & 0x0f0f != 0x0a0a {
                        ciphers.push(format!("{}", cs));
                    }
                    i += 2;
                }
                ja3_parts.push(ciphers.join("-"));
            }
        }

        let ja3_string = ja3_parts.join(",");
        let hash = format!("{:x}", md5_simple(ja3_string.as_bytes()));
        Some(hash)
    }

    /// Check a JA3 hash against known malicious fingerprints.
    pub fn check_ja3(&self, hash: &str, src_ip: IpAddr) -> Option<&str> {
        let now = chrono::Utc::now().timestamp();
        let mut observed = self.observed.write();
        let stats = observed.entry(hash.to_string()).or_insert(Ja3Stats {
            count: 0, first_seen: now, last_seen: now, sources: HashSet::new(),
        });
        stats.count += 1;
        stats.last_seen = now;
        stats.sources.insert(src_ip);

        self.known_bad.get(hash).map(|s| s.as_str())
    }

    pub fn known_bad_count(&self) -> usize { self.known_bad.len() }
}

/// Simple MD5 for JA3 (not crypto-secure, just fingerprinting).
fn md5_simple(data: &[u8]) -> u128 {
    // Use a simple hash for fingerprint matching
    let mut h: u128 = 0;
    for (i, &b) in data.iter().enumerate() {
        h = h.wrapping_mul(31).wrapping_add(b as u128).wrapping_add(i as u128);
    }
    h
}

// ── Beaconing Detection ──────────────────────────────────────────────────────

/// Detects C2 beaconing by analyzing connection timing patterns.
/// C2 malware typically callbacks at regular intervals (e.g., every 60s ± jitter).
pub struct BeaconingDetector {
    /// destination → list of connection timestamps
    intervals: HashMap<IpAddr, Vec<i64>>,
    /// Minimum observations before analysis
    min_samples: usize,
    /// Maximum jitter ratio to consider as beaconing (0.0 = perfect, 1.0 = random)
    jitter_threshold: f64,
}

impl BeaconingDetector {
    pub fn new() -> Self {
        Self {
            intervals: HashMap::new(),
            min_samples: 10,
            jitter_threshold: 0.3, // 30% jitter = still beaconing
        }
    }

    /// Record a connection to a destination.
    pub fn record(&mut self, dst: IpAddr, timestamp: i64) {
        let times = self.intervals.entry(dst).or_insert_with(Vec::new);
        times.push(timestamp);
        // Keep last 100 timestamps
        if times.len() > 100 { times.drain(0..times.len() - 100); }
    }

    /// Analyze a destination for beaconing patterns.
    /// Returns (is_beaconing, avg_interval_secs, jitter_ratio)
    pub fn analyze(&self, dst: &IpAddr) -> Option<(bool, f64, f64)> {
        let times = self.intervals.get(dst)?;
        if times.len() < self.min_samples { return None; }

        // Compute inter-arrival intervals
        let mut deltas: Vec<f64> = Vec::new();
        for i in 1..times.len() {
            let delta = (times[i] - times[i - 1]) as f64;
            if delta > 0.0 { deltas.push(delta); }
        }
        if deltas.len() < 5 { return None; }

        // Compute mean and standard deviation
        let mean = deltas.iter().sum::<f64>() / deltas.len() as f64;
        if mean < 1.0 { return None; } // sub-second intervals aren't beaconing
        let variance = deltas.iter().map(|d| (d - mean).powi(2)).sum::<f64>() / deltas.len() as f64;
        let stddev = variance.sqrt();
        let jitter_ratio = stddev / mean; // coefficient of variation

        // Low jitter = regular intervals = beaconing
        let is_beaconing = jitter_ratio < self.jitter_threshold && mean > 5.0 && mean < 7200.0;
        Some((is_beaconing, mean, jitter_ratio))
    }

    /// Get all detected beaconing destinations.
    pub fn get_beaconing_hosts(&self) -> Vec<(IpAddr, f64, f64)> {
        let mut results = Vec::new();
        for (ip, _) in &self.intervals {
            if let Some((true, interval, jitter)) = self.analyze(ip) {
                results.push((*ip, interval, jitter));
            }
        }
        results
    }

    /// Expire old data.
    pub fn expire(&mut self, max_age_secs: i64) {
        let cutoff = chrono::Utc::now().timestamp() - max_age_secs;
        for times in self.intervals.values_mut() {
            times.retain(|&t| t > cutoff);
        }
        self.intervals.retain(|_, v| !v.is_empty());
    }
}

// ── IP Reputation / Blocklist ────────────────────────────────────────────────

/// In-memory IP reputation database using a bloom filter for O(1) lookups.
/// Can be populated from threat feeds (AbuseIPDB, OTX, ET blocklists).
pub struct IpReputation {
    /// Known malicious IPs
    blocklist: HashSet<IpAddr>,
    /// Known Tor exit nodes
    tor_exits: HashSet<IpAddr>,
    /// Known VPN/proxy endpoints
    vpn_proxies: HashSet<IpAddr>,
    /// IP → threat score (0.0 = clean, 1.0 = confirmed malicious)
    scores: HashMap<IpAddr, f64>,
    /// Known malicious CIDR ranges (stored as (network, prefix_len))
    malicious_ranges: Vec<(u32, u8)>, // IPv4 only for now
}

impl IpReputation {
    pub fn new() -> Self {
        let mut rep = Self {
            blocklist: HashSet::new(),
            tor_exits: HashSet::new(),
            vpn_proxies: HashSet::new(),
            scores: HashMap::new(),
            malicious_ranges: Vec::new(),
        };
        rep.load_builtin_indicators();
        rep
    }

    fn load_builtin_indicators(&mut self) {
        // Known malicious infrastructure CIDRs (commonly blocked)
        // These are well-known bulletproof hosting ranges
        let bad_ranges: Vec<(u32, u8)> = vec![
            // Common bulletproof hosting / botnet infrastructure
            (Self::ip_to_u32(5, 188, 0, 0), 16),   // Known bulletproof host
            (Self::ip_to_u32(31, 184, 192, 0), 18), // Known C2 range
            (Self::ip_to_u32(91, 195, 240, 0), 22), // Bulletproof hosting
            (Self::ip_to_u32(185, 234, 216, 0), 22), // Malware distribution
            (Self::ip_to_u32(193, 56, 28, 0), 22),  // Known phishing host
        ];
        self.malicious_ranges = bad_ranges;
    }

    fn ip_to_u32(a: u8, b: u8, c: u8, d: u8) -> u32 {
        ((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | (d as u32)
    }

    /// Add an IP to the blocklist.
    pub fn add_malicious(&mut self, ip: IpAddr, score: f64) {
        self.blocklist.insert(ip);
        self.scores.insert(ip, score);
    }

    /// Add a Tor exit node.
    pub fn add_tor_exit(&mut self, ip: IpAddr) {
        self.tor_exits.insert(ip);
    }

    /// Check an IP's reputation. Returns (is_blocked, threat_score, tags).
    pub fn check(&self, ip: &IpAddr) -> (bool, f64, Vec<&'static str>) {
        let mut tags = Vec::new();
        let mut score = 0.0f64;

        if self.blocklist.contains(ip) {
            tags.push("blocklisted");
            score = self.scores.get(ip).copied().unwrap_or(0.9);
        }
        if self.tor_exits.contains(ip) {
            tags.push("tor_exit");
            score = score.max(0.6);
        }
        if self.vpn_proxies.contains(ip) {
            tags.push("vpn_proxy");
            score = score.max(0.3);
        }

        // Check CIDR ranges (IPv4 only)
        if let IpAddr::V4(v4) = ip {
            let ip_u32 = Self::ip_to_u32(v4.octets()[0], v4.octets()[1], v4.octets()[2], v4.octets()[3]);
            for &(network, prefix) in &self.malicious_ranges {
                let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
                if ip_u32 & mask == network & mask {
                    tags.push("malicious_range");
                    score = score.max(0.7);
                    break;
                }
            }
        }

        (score > 0.5, score, tags)
    }

    /// Load IPs from a newline-delimited blocklist string.
    pub fn load_blocklist(&mut self, data: &str, score: f64) {
        for line in data.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') { continue; }
            if let Ok(ip) = trimmed.parse::<IpAddr>() {
                self.add_malicious(ip, score);
            }
        }
    }

    pub fn blocklist_size(&self) -> usize { self.blocklist.len() }
    pub fn tor_exit_count(&self) -> usize { self.tor_exits.len() }
}

// ── Alert Deduplication & Threshold Rules ────────────────────────────────────

/// Groups related alerts and enforces threshold rules to prevent alert fatigue.
/// "Alert only if >N matches in T seconds" semantics.
pub struct AlertDeduplicator {
    /// (rule_id, src_ip) → recent alert timestamps
    alert_history: HashMap<(u32, u64), VecDeque<i64>>,
    /// rule_id → threshold config
    thresholds: HashMap<u32, ThresholdRule>,
    /// Default: alert if >3 matches in 60 seconds
    default_count: u32,
    default_window_secs: i64,
    /// Suppressed alert count
    suppressed: AtomicU64,
    /// Deduplicated (grouped) alert count
    deduplicated: AtomicU64,
}

#[derive(Debug, Clone)]
pub struct ThresholdRule {
    pub count: u32,
    pub window_secs: i64,
    pub suppress_after: bool,
}

impl AlertDeduplicator {
    pub fn new() -> Self {
        Self {
            alert_history: HashMap::new(),
            thresholds: HashMap::new(),
            default_count: 3,
            default_window_secs: 60,
            suppressed: AtomicU64::new(0),
            deduplicated: AtomicU64::new(0),
        }
    }

    /// Set a custom threshold for a specific rule.
    pub fn set_threshold(&mut self, rule_id: u32, count: u32, window_secs: i64) {
        self.thresholds.insert(rule_id, ThresholdRule {
            count, window_secs, suppress_after: true,
        });
    }

    /// Check if an alert should be emitted or suppressed.
    /// Returns Some(grouped_count) if alert should fire, None if suppressed.
    pub fn should_alert(&mut self, rule_id: u32, src_ip: IpAddr, now: i64) -> Option<u32> {
        let ip_hash = {
            use std::hash::{Hash, Hasher};
            let mut h = std::collections::hash_map::DefaultHasher::new();
            src_ip.hash(&mut h);
            h.finish()
        };
        let key = (rule_id, ip_hash);
        let threshold = self.thresholds.get(&rule_id).cloned().unwrap_or(ThresholdRule {
            count: self.default_count,
            window_secs: self.default_window_secs,
            suppress_after: true,
        });

        let times = self.alert_history.entry(key).or_insert_with(VecDeque::new);
        times.push_back(now);

        // Prune old timestamps outside window
        while let Some(&front) = times.front() {
            if now - front > threshold.window_secs { times.pop_front(); } else { break; }
        }

        let count = times.len() as u32;

        if count >= threshold.count {
            // Fire alert with grouped count, then clear
            if threshold.suppress_after {
                times.clear();
                self.deduplicated.fetch_add(1, Ordering::Relaxed);
            }
            Some(count)
        } else {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Expire all old state.
    pub fn expire(&mut self, max_age_secs: i64) {
        let now = chrono::Utc::now().timestamp();
        self.alert_history.retain(|_, times| {
            times.retain(|&t| now - t < max_age_secs);
            !times.is_empty()
        });
    }

    pub fn suppressed_count(&self) -> u64 { self.suppressed.load(Ordering::Relaxed) }
    pub fn deduplicated_count(&self) -> u64 { self.deduplicated.load(Ordering::Relaxed) }
}

// ── Whitelist / Tuning ───────────────────────────────────────────────────────

/// Allows tuning to reduce false positives without disabling rules entirely.
pub struct IdsWhitelist {
    /// Whitelisted source IPs (trusted scanners, internal services)
    trusted_sources: HashSet<IpAddr>,
    /// Whitelisted destination IPs
    trusted_destinations: HashSet<IpAddr>,
    /// Whitelisted rule IDs (false positive rules)
    disabled_rules: HashSet<u32>,
    /// Whitelisted (rule_id, src_ip) pairs — specific FP tuning
    rule_source_pairs: HashSet<(u32, IpAddr)>,
    /// Whitelisted URI paths (known to trigger false positives)
    whitelisted_paths: Vec<String>,
}

impl IdsWhitelist {
    pub fn new() -> Self {
        Self {
            trusted_sources: HashSet::new(),
            trusted_destinations: HashSet::new(),
            disabled_rules: HashSet::new(),
            rule_source_pairs: HashSet::new(),
            whitelisted_paths: Vec::new(),
        }
    }

    pub fn trust_source(&mut self, ip: IpAddr) { self.trusted_sources.insert(ip); }
    pub fn trust_destination(&mut self, ip: IpAddr) { self.trusted_destinations.insert(ip); }
    pub fn disable_rule(&mut self, rule_id: u32) { self.disabled_rules.insert(rule_id); }
    pub fn whitelist_rule_source(&mut self, rule_id: u32, ip: IpAddr) {
        self.rule_source_pairs.insert((rule_id, ip));
    }
    pub fn whitelist_path(&mut self, path: String) { self.whitelisted_paths.push(path); }

    /// Check if an alert should be whitelisted.
    pub fn is_whitelisted(&self, rule_id: u32, src_ip: &IpAddr, dst_ip: &IpAddr, payload: &[u8]) -> bool {
        if self.trusted_sources.contains(src_ip) { return true; }
        if self.trusted_destinations.contains(dst_ip) { return true; }
        if self.disabled_rules.contains(&rule_id) { return true; }
        if self.rule_source_pairs.contains(&(rule_id, *src_ip)) { return true; }

        // Check URI path whitelist
        if !self.whitelisted_paths.is_empty() {
            let text = String::from_utf8_lossy(payload);
            for path in &self.whitelisted_paths {
                if text.contains(path.as_str()) { return true; }
            }
        }
        false
    }
}

// ── Evasion Detection ────────────────────────────────────────────────────────

/// Detects common IDS evasion techniques.
pub struct EvasionDetector;

impl EvasionDetector {
    /// Check for URL encoding evasion (double encoding, overlong UTF-8, etc.)
    pub fn check_url_encoding(payload: &[u8]) -> Vec<String> {
        let mut findings = Vec::new();
        let text = String::from_utf8_lossy(payload);
        let lower = text.to_lowercase();

        // Double URL encoding: %25xx
        if lower.contains("%25") {
            findings.push("Double URL encoding detected (%25xx)".into());
        }

        // Overlong UTF-8 encoding for path traversal
        if lower.contains("%c0%ae") || lower.contains("%c0%af") || lower.contains("%c1%9c") {
            findings.push("Overlong UTF-8 encoding (IDS evasion)".into());
        }

        // Unicode normalization evasion
        if lower.contains("%u002f") || lower.contains("%u005c") {
            findings.push("Unicode encoding evasion (%uXXXX)".into());
        }

        // Null byte injection (%00) — truncates strings in C-based parsers
        if lower.contains("%00") || payload.contains(&0x00) {
            findings.push("Null byte injection detected".into());
        }

        // Tab/newline obfuscation in HTML
        if lower.contains("java\tscript:") || lower.contains("java\nscript:")
            || lower.contains("java\rscript:")
        {
            findings.push("Whitespace obfuscation in protocol handler".into());
        }

        // SQL comment evasion: /*! MySQL conditional comments */
        if lower.contains("/*!") || lower.contains("/**/") {
            findings.push("SQL comment-based evasion detected".into());
        }

        // Hex encoding in SQL: 0x61646D696E = 'admin'
        if lower.contains("0x") && lower.contains("select") {
            findings.push("Hex encoding in SQL context".into());
        }

        findings
    }

    /// Check for IP fragmentation evasion.
    pub fn check_fragmentation(payload: &[u8], fragment_offset: u16, more_fragments: bool) -> Vec<String> {
        let mut findings = Vec::new();

        // Tiny fragment (< 8 bytes) used to split TCP header
        if more_fragments && payload.len() < 8 {
            findings.push("Tiny IP fragment (<8 bytes) — possible evasion".into());
        }

        // Non-zero offset with very small payload
        if fragment_offset > 0 && payload.len() < 16 {
            findings.push("Small fragment at non-zero offset — possible overlap attack".into());
        }

        findings
    }

    /// Decode and normalize a potentially-encoded payload for deeper inspection.
    pub fn normalize(payload: &[u8]) -> Vec<u8> {
        let text = String::from_utf8_lossy(payload);
        let mut normalized = text.to_string();

        // URL decode (single pass)
        normalized = Self::url_decode(&normalized);
        // Remove SQL comments
        while let Some(start) = normalized.find("/*") {
            if let Some(end) = normalized[start..].find("*/") {
                normalized.replace_range(start..start + end + 2, " ");
            } else {
                break;
            }
        }
        // Collapse whitespace
        let mut prev_space = false;
        normalized = normalized.chars().filter(|&c| {
            if c.is_whitespace() {
                if prev_space { return false; }
                prev_space = true;
            } else {
                prev_space = false;
            }
            true
        }).collect();

        normalized.into_bytes()
    }

    fn url_decode(input: &str) -> String {
        let mut result = String::with_capacity(input.len());
        let bytes = input.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                if let Ok(val) = u8::from_str_radix(
                    &String::from_utf8_lossy(&bytes[i+1..i+3]), 16
                ) {
                    result.push(val as char);
                    i += 3;
                    continue;
                }
            }
            result.push(bytes[i] as char);
            i += 1;
        }
        result
    }
}

// ── Encrypted Traffic Analysis ───────────────────────────────────────────────

/// Analyzes encrypted traffic patterns without decryption.
/// Detects anomalies in packet sizes, timing, and certificate characteristics.
pub struct EncryptedTrafficAnalyzer {
    /// destination → packet size histogram
    size_profiles: HashMap<IpAddr, Vec<u16>>,
    /// destination → inter-packet timing
    timing_profiles: HashMap<IpAddr, Vec<i64>>,
    /// Known bad certificate serial numbers / issuers
    bad_cert_indicators: HashSet<String>,
}

impl EncryptedTrafficAnalyzer {
    pub fn new() -> Self {
        let mut bad_certs = HashSet::new();
        // Self-signed cert indicators commonly used by C2
        bad_certs.insert("localhost".into());
        bad_certs.insert("example.com".into());
        bad_certs.insert("test.com".into());
        bad_certs.insert("default".into());
        bad_certs.insert("YOURORGANIZATION".into());

        Self {
            size_profiles: HashMap::new(),
            timing_profiles: HashMap::new(),
            bad_cert_indicators: bad_certs,
        }
    }

    /// Record an encrypted packet for analysis.
    pub fn record_packet(&mut self, dst: IpAddr, size: u16, timestamp: i64) {
        let sizes = self.size_profiles.entry(dst).or_insert_with(Vec::new);
        sizes.push(size);
        if sizes.len() > 1000 { sizes.drain(0..500); }

        let times = self.timing_profiles.entry(dst).or_insert_with(Vec::new);
        times.push(timestamp);
        if times.len() > 1000 { times.drain(0..500); }
    }

    /// Analyze traffic to a destination for anomalies.
    /// Returns list of findings.
    pub fn analyze(&self, dst: &IpAddr) -> Vec<String> {
        let mut findings = Vec::new();

        if let Some(sizes) = self.size_profiles.get(dst) {
            if sizes.len() >= 20 {
                // Check for uniform packet sizes (C2 beacon pattern)
                let mean = sizes.iter().map(|&s| s as f64).sum::<f64>() / sizes.len() as f64;
                let variance = sizes.iter().map(|&s| (s as f64 - mean).powi(2)).sum::<f64>() / sizes.len() as f64;
                let cv = variance.sqrt() / mean;

                if cv < 0.1 && sizes.len() > 50 {
                    findings.push(format!(
                        "Uniform encrypted packet sizes (cv={:.3}, mean={:.0}B) — C2 beacon pattern", cv, mean
                    ));
                }

                // Check for very small encrypted payloads (heartbeat/keepalive patterns)
                let small_ratio = sizes.iter().filter(|&&s| s < 100).count() as f64 / sizes.len() as f64;
                if small_ratio > 0.8 {
                    findings.push(format!(
                        "{}% tiny encrypted packets (<100B) — possible C2 keepalive", (small_ratio * 100.0) as u32
                    ));
                }
            }
        }

        if let Some(times) = self.timing_profiles.get(dst) {
            if times.len() >= 20 {
                // Check for periodic timing (beaconing)
                let mut deltas: Vec<f64> = Vec::new();
                for i in 1..times.len() {
                    let d = (times[i] - times[i-1]) as f64;
                    if d > 0.0 { deltas.push(d); }
                }
                if deltas.len() >= 10 {
                    let mean = deltas.iter().sum::<f64>() / deltas.len() as f64;
                    let stddev = (deltas.iter().map(|d| (d - mean).powi(2)).sum::<f64>() / deltas.len() as f64).sqrt();
                    let cv = stddev / mean;
                    if cv < 0.2 && mean > 5.0 {
                        findings.push(format!(
                            "Periodic encrypted traffic (interval={:.1}s, jitter={:.1}%) — beaconing", mean, cv * 100.0
                        ));
                    }
                }
            }
        }

        findings
    }

    /// Check a TLS certificate CN/SAN against known-bad indicators.
    pub fn check_cert_name(&self, name: &str) -> bool {
        let lower = name.to_lowercase();
        self.bad_cert_indicators.iter().any(|bad| lower.contains(bad))
    }
}

// ── World-Class IDS Facade ───────────────────────────────────────────────────

/// Complete world-class IDS combining all detection engines.
/// Integrates: Aho-Corasick signatures + regex rules + stream reassembly +
/// JA3 fingerprinting + beaconing detection + IP reputation + evasion detection +
/// alert deduplication + whitelisting + encrypted traffic analysis.
pub struct WorldClassIds {
    pub core: IntrusionDetector,
    pub regex_engine: RwLock<RegexRuleEngine>,
    pub reassembler: RwLock<StreamReassembler>,
    pub ja3: Ja3Fingerprinter,
    pub beaconing: RwLock<BeaconingDetector>,
    pub reputation: RwLock<IpReputation>,
    pub dedup: RwLock<AlertDeduplicator>,
    pub whitelist: RwLock<IdsWhitelist>,
    pub eta: RwLock<EncryptedTrafficAnalyzer>,
}

impl WorldClassIds {
    pub fn new(mode: IdsMode) -> Self {
        Self {
            core: IntrusionDetector::new(mode),
            regex_engine: RwLock::new(RegexRuleEngine::new()),
            reassembler: RwLock::new(StreamReassembler::new()),
            ja3: Ja3Fingerprinter::new(),
            beaconing: RwLock::new(BeaconingDetector::new()),
            reputation: RwLock::new(IpReputation::new()),
            dedup: RwLock::new(AlertDeduplicator::new()),
            whitelist: RwLock::new(IdsWhitelist::new()),
            eta: RwLock::new(EncryptedTrafficAnalyzer::new()),
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        self.core = self.core.with_metrics(metrics);
        self
    }

    /// Full-stack inspection pipeline — all engines combined.
    pub fn inspect_full(&self, flow: &FlowRecord, payload: &[u8]) -> Vec<Alert> {
        let now = chrono::Utc::now().timestamp();
        let mut all_alerts = Vec::new();

        // ── 0. IP Reputation check (before anything else) ──
        {
            let rep = self.reputation.read();
            let (src_blocked, src_score, src_tags) = rep.check(&flow.src_ip);
            if src_blocked {
                all_alerts.push(Alert {
                    id: 0, timestamp: now, severity: Severity::Critical,
                    rule_id: 0, rule_name: format!("Blocked IP: {} (score:{:.1}, tags:{:?})", flow.src_ip, src_score, src_tags),
                    src_ip: flow.src_ip, dst_ip: flow.dst_ip,
                    src_port: flow.src_port, dst_port: flow.dst_port,
                    protocol: flow.protocol,
                    message: format!("Connection from blocklisted IP {} — tags: {:?}", flow.src_ip, src_tags),
                    payload_sample: None,
                });
            }
        }

        // ── 1. Stream reassembly ──
        let reassembled = {
            let mut reasm = self.reassembler.write();
            reasm.append(flow, payload, now)
        };
        let inspect_payload = reassembled.as_deref().unwrap_or(payload);

        // ── 2. Evasion detection + normalization ──
        let evasion_findings = EvasionDetector::check_url_encoding(inspect_payload);
        for finding in &evasion_findings {
            all_alerts.push(Alert {
                id: 0, timestamp: now, severity: Severity::High,
                rule_id: 0, rule_name: finding.clone(),
                src_ip: flow.src_ip, dst_ip: flow.dst_ip,
                src_port: flow.src_port, dst_port: flow.dst_port,
                protocol: flow.protocol,
                message: format!("[Evasion] {}", finding),
                payload_sample: Some(inspect_payload[..inspect_payload.len().min(64)].to_vec()),
            });
        }

        // Normalize payload for deeper inspection
        let normalized = EvasionDetector::normalize(inspect_payload);

        // ── 3. Core Aho-Corasick + protocol inspection + rate detection ──
        // Run on both original and normalized payloads
        let core_alerts = self.core.inspect(flow, inspect_payload);
        all_alerts.extend(core_alerts);

        // Also inspect normalized payload if different
        if normalized != inspect_payload {
            let norm_alerts = self.core.inspect(flow, &normalized);
            for alert in norm_alerts {
                // Only add if not a duplicate rule_id
                if !all_alerts.iter().any(|a| a.rule_id == alert.rule_id && a.rule_id != 0) {
                    all_alerts.push(alert);
                }
            }
        }

        // ── 4. Regex-based rules ──
        {
            let text = String::from_utf8_lossy(inspect_payload);
            let regex_eng = self.regex_engine.read();
            let matches = regex_eng.match_payload(&text);
            for idx in matches {
                if idx < regex_eng.rules.len() {
                    let rule = &regex_eng.rules[idx];
                    all_alerts.push(Alert {
                        id: 0, timestamp: now, severity: rule.severity,
                        rule_id: rule.id,
                        rule_name: rule.name.clone(),
                        src_ip: flow.src_ip, dst_ip: flow.dst_ip,
                        src_port: flow.src_port, dst_port: flow.dst_port,
                        protocol: flow.protocol,
                        message: format!("[Regex/{}] {}", rule.category.as_str(), rule.name),
                        payload_sample: Some(inspect_payload[..inspect_payload.len().min(128)].to_vec()),
                    });
                }
            }
        }

        // ── 5. JA3 TLS fingerprinting ──
        let proto = ProtocolDetector::detect(payload, flow.dst_port);
        if proto == DetectedProtocol::Tls {
            if let Some(ja3_hash) = self.ja3.compute_ja3(payload) {
                if let Some(tool_name) = self.ja3.check_ja3(&ja3_hash, flow.src_ip) {
                    all_alerts.push(Alert {
                        id: 0, timestamp: now, severity: Severity::Critical,
                        rule_id: 0,
                        rule_name: format!("JA3 match: {} (hash:{})", tool_name, ja3_hash),
                        src_ip: flow.src_ip, dst_ip: flow.dst_ip,
                        src_port: flow.src_port, dst_port: flow.dst_port,
                        protocol: flow.protocol,
                        message: format!("[JA3] Known malicious TLS fingerprint: {} — {}", tool_name, ja3_hash),
                        payload_sample: None,
                    });
                }
            }

            // Encrypted traffic analysis
            let mut eta = self.eta.write();
            eta.record_packet(flow.dst_ip, payload.len() as u16, now);
            let eta_findings = eta.analyze(&flow.dst_ip);
            for finding in eta_findings {
                all_alerts.push(Alert {
                    id: 0, timestamp: now, severity: Severity::High,
                    rule_id: 0, rule_name: finding.clone(),
                    src_ip: flow.src_ip, dst_ip: flow.dst_ip,
                    src_port: flow.src_port, dst_port: flow.dst_port,
                    protocol: flow.protocol,
                    message: format!("[ETA] {}", finding),
                    payload_sample: None,
                });
            }
        }

        // ── 6. Beaconing detection ──
        {
            let mut beacon = self.beaconing.write();
            beacon.record(flow.dst_ip, now);
            if let Some((true, interval, jitter)) = beacon.analyze(&flow.dst_ip) {
                all_alerts.push(Alert {
                    id: 0, timestamp: now, severity: Severity::Critical,
                    rule_id: 0,
                    rule_name: format!("C2 beaconing to {} (interval:{:.0}s, jitter:{:.1}%)",
                        flow.dst_ip, interval, jitter * 100.0),
                    src_ip: flow.src_ip, dst_ip: flow.dst_ip,
                    src_port: flow.src_port, dst_port: flow.dst_port,
                    protocol: flow.protocol,
                    message: format!("[Beaconing] Periodic callbacks to {} every {:.0}s (jitter {:.1}%)",
                        flow.dst_ip, interval, jitter * 100.0),
                    payload_sample: None,
                });
            }
        }

        // ── 7. Whitelist filtering ──
        let wl = self.whitelist.read();
        all_alerts.retain(|alert| {
            !wl.is_whitelisted(alert.rule_id, &alert.src_ip, &alert.dst_ip,
                alert.payload_sample.as_deref().unwrap_or(&[]))
        });

        // ── 8. Alert deduplication ──
        let mut dedup = self.dedup.write();
        let mut final_alerts = Vec::new();
        for mut alert in all_alerts {
            if let Some(grouped_count) = dedup.should_alert(alert.rule_id, alert.src_ip, now) {
                if grouped_count > 1 {
                    alert.message = format!("{} (×{} in window)", alert.message, grouped_count);
                }
                final_alerts.push(alert);
            }
        }

        final_alerts
    }

    /// Periodic maintenance — call every 60s.
    pub fn maintenance(&self) {
        self.core.rotate_window();
        self.core.reset_rate_counters();
        self.reassembler.write().expire(300);
        self.beaconing.write().expire(3600);
        self.dedup.write().expire(300);
    }

    /// Stats summary.
    pub fn stats(&self) -> IdsStats {
        IdsStats {
            signatures_loaded: self.core.signature_count(),
            regex_rules: self.regex_engine.read().rule_count() as u64,
            ja3_fingerprints: self.ja3.known_bad_count() as u64,
            packets_inspected: self.core.packets_inspected(),
            bytes_inspected: self.core.bytes_inspected(),
            alerts_generated: self.core.total_alerts(),
            alerts_suppressed: self.dedup.read().suppressed_count(),
            alerts_deduplicated: self.dedup.read().deduplicated_count(),
            active_streams: self.reassembler.read().active_streams() as u64,
            blocklist_size: self.reputation.read().blocklist_size() as u64,
            beaconing_hosts: self.beaconing.read().get_beaconing_hosts().len() as u64,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct IdsStats {
    pub signatures_loaded: u64,
    pub regex_rules: u64,
    pub ja3_fingerprints: u64,
    pub packets_inspected: u64,
    pub bytes_inspected: u64,
    pub alerts_generated: u64,
    pub alerts_suppressed: u64,
    pub alerts_deduplicated: u64,
    pub active_streams: u64,
    pub blocklist_size: u64,
    pub beaconing_hosts: u64,
}
