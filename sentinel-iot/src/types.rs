//! Shared types for the IoT Security Layer.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IoTAlert {
    pub timestamp: i64,
    pub severity: Severity,
    pub component: String,
    pub title: String,
    pub details: String,
    pub device_id: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IoTDevice {
    pub device_id: String,
    pub name: String,
    pub device_type: DeviceType,
    pub firmware_version: String,
    pub ip_address: Option<String>,
    pub mac_address: Option<String>,
    pub registered_at: i64,
    pub last_seen: Option<i64>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DeviceType {
    Sensor,
    Actuator,
    Gateway,
    Camera,
    Controller,
    Wearable,
    Industrial,
    Medical,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DeviceStatus {
    Online,
    Offline,
    Degraded,
    Compromised,
    Quarantined,
}
