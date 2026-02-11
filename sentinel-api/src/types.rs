//! Shared types for the API Security Layer.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub enum Severity { Low, Medium, High, Critical }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ApiAlert {
    pub timestamp: i64,
    pub severity: Severity,
    pub component: String,
    pub title: String,
    pub details: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ApiThreat { Injection, BrokenAuth, ExcessiveData, RateLimitBypass, MassAssignment, Ssrf }
