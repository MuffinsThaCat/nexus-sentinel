//! Shared types for the DNS Security Layer.

/// DNS record types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum RecordType {
    A,
    AAAA,
    CNAME,
    MX,
    NS,
    TXT,
    SOA,
    PTR,
    SRV,
    CAA,
    NULL,
    Other,
}

/// A DNS query.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsQuery {
    pub domain: String,
    pub record_type: RecordType,
    pub source_ip: String,
    pub timestamp: i64,
}

/// A DNS response.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsResponse {
    pub domain: String,
    pub record_type: RecordType,
    pub answers: Vec<String>,
    pub ttl: u32,
    pub response_code: ResponseCode,
    pub timestamp: i64,
}

/// DNS response codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ResponseCode {
    NoError,
    FormErr,
    ServFail,
    NxDomain,
    NotImp,
    Refused,
    Other(u16),
}

/// Severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// DNS security alert.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsAlert {
    pub timestamp: i64,
    pub severity: Severity,
    pub component: String,
    pub title: String,
    pub details: String,
    pub domain: Option<String>,
    pub source_ip: Option<String>,
}

/// Verdict for a DNS query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DnsVerdict {
    Allow,
    Block,
    Sinkhole,
    RateLimit,
}
