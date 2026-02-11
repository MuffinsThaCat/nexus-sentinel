//! Shared types for the SIEM / Log Management Layer.

/// Log severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

/// A structured log event.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LogEvent {
    pub id: String,
    pub timestamp: i64,
    pub level: LogLevel,
    pub source: String,
    pub component: String,
    pub message: String,
    pub fields: std::collections::HashMap<String, String>,
}

/// SIEM alert.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SiemAlert {
    pub id: String,
    pub timestamp: i64,
    pub severity: LogLevel,
    pub rule_name: String,
    pub title: String,
    pub details: String,
    pub source_events: Vec<String>,
    pub acknowledged: bool,
}

/// Correlation rule definition.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CorrelationRule {
    pub name: String,
    pub description: String,
    pub pattern: RulePattern,
    pub severity: LogLevel,
    pub window_secs: i64,
    pub threshold: u32,
    pub enabled: bool,
}

/// Rule pattern types.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum RulePattern {
    /// Match events with specific field values
    FieldMatch { field: String, value: String },
    /// Match events exceeding a count threshold from same source
    CountThreshold { source_field: String },
    /// Match a sequence of event types
    Sequence { components: Vec<String> },
}

/// Log source configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LogSource {
    pub name: String,
    pub source_type: SourceType,
    pub enabled: bool,
}

/// Types of log sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SourceType {
    Syslog,
    FileLog,
    WindowsEventLog,
    Api,
    Agent,
    Custom,
}
