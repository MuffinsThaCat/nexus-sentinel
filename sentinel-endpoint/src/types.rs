//! Endpoint Security — Shared types
//!
//! Data structures for endpoint (host-level) security monitoring.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A process observed on the endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub exe_path: PathBuf,
    pub cmdline: String,
    pub user: String,
    pub start_time: i64,
    pub cpu_percent: f32,
    pub memory_bytes: u64,
    pub open_files: u32,
    pub open_sockets: u32,
}

/// A file system event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    pub path: PathBuf,
    pub event_type: FileEventType,
    pub timestamp: i64,
    pub process_name: Option<String>,
    pub process_pid: Option<u32>,
    pub size_bytes: Option<u64>,
    pub hash_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileEventType {
    Created,
    Modified,
    Deleted,
    Renamed,
    PermissionChanged,
    Accessed,
}

/// Severity levels for endpoint alerts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// An endpoint security alert.
#[derive(Debug, Clone, Serialize)]
pub struct EndpointAlert {
    pub timestamp: i64,
    pub severity: Severity,
    pub component: String,
    pub title: String,
    pub details: String,
    pub process: Option<ProcessInfo>,
    pub file: Option<FileEvent>,
}

/// USB device info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDevice {
    pub vendor_id: u16,
    pub product_id: u16,
    pub vendor_name: String,
    pub product_name: String,
    pub serial: Option<String>,
    pub device_class: UsbDeviceClass,
    pub connected_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UsbDeviceClass {
    Storage,
    HumanInterface,
    Network,
    Audio,
    Video,
    Printer,
    Wireless,
    Other,
}

/// Registry / config change (cross-platform abstraction).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigChange {
    pub path: String,
    pub key: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub timestamp: i64,
    pub process_name: Option<String>,
}
