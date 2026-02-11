//! Shared types for the Web Security Layer.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub enum Severity { Low, Medium, High, Critical }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WebAlert {
    pub timestamp: i64,
    pub severity: Severity,
    pub component: String,
    pub title: String,
    pub details: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum AttackType {
    Xss, SqlInjection, Csrf, PathTraversal, CommandInjection, Ssrf, Rfi,
    Lfi, Xxe, Ssti, LdapInjection, HeaderInjection, OpenRedirect,
    PrototypePolllution, HttpSmuggling, BotAbuse, RateLimitExceeded,
    MaliciousUpload, DirectoryListing, InfoLeakage,
}
