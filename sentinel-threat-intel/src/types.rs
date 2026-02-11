//! Shared types for the Threat Intelligence Layer.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub enum Severity { Low, Medium, High, Critical }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ThreatAlert {
    pub timestamp: i64,
    pub severity: Severity,
    pub component: String,
    pub title: String,
    pub details: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum IocType { IpAddress, Domain, Url, FileHash, Email, Registry, Mutex }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Ioc {
    pub ioc_type: IocType,
    pub value: String,
    pub source: String,
    pub confidence: u8,
    pub first_seen: i64,
    pub last_seen: i64,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ThreatLevel { Unknown, Benign, Suspicious, Malicious }
