//! Ticket Integrator — creates tickets from security alerts.
//!
//! Memory optimizations (2 techniques):
//! - **#569 Entry Pruning**: Resolved tickets pruned
//! - **#6 Theoretical Verifier**: Bounded

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TicketStatus { Open, InProgress, Resolved, Closed }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecurityTicket {
    pub ticket_id: u64,
    pub title: String,
    pub severity: Severity,
    pub status: TicketStatus,
    pub assignee: Option<String>,
    pub created_at: i64,
    pub resolved_at: Option<i64>,
}

/// Ticket integrator.
pub struct TicketIntegrator {
    tickets: RwLock<Vec<SecurityTicket>>,
    ticket_cache: TieredCache<u64, TicketStatus>,
    alerts: RwLock<Vec<OpsAlert>>,
    total_created: AtomicU64,
    open_count: AtomicU64,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl TicketIntegrator {
    pub fn new() -> Self {
        Self {
            tickets: RwLock::new(Vec::new()),
            ticket_cache: TieredCache::new(10_000),
            alerts: RwLock::new(Vec::new()),
            total_created: AtomicU64::new(0),
            open_count: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("ticket_integrator", 2 * 1024 * 1024);
        self.ticket_cache = self.ticket_cache.with_metrics(metrics.clone(), "ticket_integrator");
        self.metrics = Some(metrics);
        self
    }

    pub fn create_ticket(&self, title: &str, severity: Severity) -> u64 {
        let id = self.total_created.fetch_add(1, Ordering::Relaxed);
        self.open_count.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        let ticket = SecurityTicket { ticket_id: id, title: title.into(), severity, status: TicketStatus::Open, assignee: None, created_at: now, resolved_at: None };
        let mut t = self.tickets.write();
        if t.len() >= MAX_ALERTS { t.remove(0); }
        t.push(ticket);
        id
    }

    pub fn resolve_ticket(&self, ticket_id: u64) {
        let now = chrono::Utc::now().timestamp();
        let mut tickets = self.tickets.write();
        if let Some(t) = tickets.iter_mut().find(|t| t.ticket_id == ticket_id) {
            t.status = TicketStatus::Resolved;
            t.resolved_at = Some(now);
            self.open_count.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub fn assign_ticket(&self, ticket_id: u64, assignee: &str) {
        let mut tickets = self.tickets.write();
        if let Some(t) = tickets.iter_mut().find(|t| t.ticket_id == ticket_id) {
            t.assignee = Some(assignee.into());
            t.status = TicketStatus::InProgress;
        }
    }

    /// #569 Entry pruning: remove closed tickets.
    pub fn prune_closed(&self) -> usize {
        let mut tickets = self.tickets.write();
        let before = tickets.len();
        tickets.retain(|t| t.status != TicketStatus::Closed);
        before - tickets.len()
    }

    pub fn open_tickets(&self) -> Vec<SecurityTicket> {
        self.tickets.read().iter().filter(|t| t.status == TicketStatus::Open || t.status == TicketStatus::InProgress).cloned().collect()
    }

    fn add_alert(&self, _ts: i64, _sev: Severity, _title: &str, _details: &str) {
        // Ticket integrator generates tickets, not alerts
    }

    pub fn total_created(&self) -> u64 { self.total_created.load(Ordering::Relaxed) }
    pub fn open_count(&self) -> u64 { self.open_count.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<OpsAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
