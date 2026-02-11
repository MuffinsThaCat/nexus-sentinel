//! Shared types for the Vulnerability Management Layer.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub enum Severity { Low, Medium, High, Critical }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VulnAlert {
    pub timestamp: i64,
    pub severity: Severity,
    pub component: String,
    pub title: String,
    pub details: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum VulnStatus { Open, Acknowledged, Mitigated, Patched, Accepted }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Vulnerability {
    pub cve_id: String,
    pub title: String,
    pub cvss_score: f64,
    pub severity: Severity,
    pub affected_asset: String,
    pub status: VulnStatus,
    pub discovered_at: i64,
}
