//! Shared types for the Identity Security Layer.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IdentityAlert {
    pub timestamp: i64,
    pub severity: Severity,
    pub component: String,
    pub title: String,
    pub details: String,
    pub user_id: Option<String>,
    pub source_ip: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UserIdentity {
    pub user_id: String,
    pub username: String,
    pub email: Option<String>,
    pub roles: Vec<String>,
    pub groups: Vec<String>,
    pub enabled: bool,
    pub created_at: i64,
    pub last_login: Option<i64>,
    pub mfa_enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AuthResult {
    Success,
    FailedCredentials,
    FailedMfa,
    AccountLocked,
    AccountDisabled,
    Expired,
    Denied,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuthEvent {
    pub timestamp: i64,
    pub user_id: String,
    pub source_ip: String,
    pub result: AuthResult,
    pub method: AuthMethod,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AuthMethod {
    Password,
    Token,
    Certificate,
    Sso,
    ApiKey,
    Biometric,
}
