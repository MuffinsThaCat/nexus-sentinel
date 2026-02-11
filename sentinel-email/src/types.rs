//! Shared types for the Email Security Layer.

use std::path::PathBuf;

/// Severity levels for email alerts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Email message representation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EmailMessage {
    pub id: String,
    pub from: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub subject: String,
    pub body_text: Option<String>,
    pub body_html: Option<String>,
    pub headers: Vec<(String, String)>,
    pub attachments: Vec<Attachment>,
    pub received_at: i64,
    pub size_bytes: usize,
}

/// Email attachment.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Attachment {
    pub filename: String,
    pub mime_type: String,
    pub size_bytes: usize,
    pub hash_sha256: String,
    pub path: Option<PathBuf>,
}

/// Email security alert.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EmailAlert {
    pub timestamp: i64,
    pub severity: Severity,
    pub component: String,
    pub title: String,
    pub details: String,
    pub email_id: Option<String>,
    pub sender: Option<String>,
}

/// Verdict for an email check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious,
    Quarantined,
    Rejected,
}

/// Authentication result for SPF/DKIM/DMARC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AuthResult {
    Pass,
    Fail,
    SoftFail,
    Neutral,
    None,
    TempError,
    PermError,
}
