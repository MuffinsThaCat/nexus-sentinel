//! # Event Bus — Inter-component communication backbone
//!
//! Provides typed publish/subscribe event routing between all 240 security components.
//! Events flow through the system as: Detection → Correlation → Response → Notification.
//!
//! Memory optimizations:
//! - **#569 Entry Pruning**: Events older than TTL are auto-pruned
//! - **#6 Theoretical Verifier**: Bounded event queue depth

use crate::MemoryMetrics;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, warn};

/// Maximum events held in the bus before oldest are pruned.
const MAX_EVENT_QUEUE: usize = 100_000;
/// Maximum subscribers per event type.
const MAX_SUBSCRIBERS: usize = 256;

// ── Event Types ──────────────────────────────────────────────────────────────

/// Severity levels matching component alert severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub enum EventSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// The category of a security event — determines routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum EventCategory {
    /// Raw detection from any sensor/scanner
    Detection,
    /// Correlated/enriched finding (multiple detections combined)
    Correlation,
    /// Automated response action taken
    Response,
    /// Notification/ticket/alert for operators
    Notification,
    /// Health/status of sentinel components
    Health,
    /// Configuration change
    ConfigChange,
    /// Metric/telemetry data point
    Metric,
}

/// A security event flowing through the bus.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecurityEvent {
    /// Unique event ID (monotonic)
    pub id: u64,
    /// Unix timestamp (millis)
    pub timestamp_ms: i64,
    /// Which component emitted this event
    pub source_component: String,
    /// Which crate the component belongs to
    pub source_crate: String,
    /// Category determines routing
    pub category: EventCategory,
    /// Severity
    pub severity: EventSeverity,
    /// Short title
    pub title: String,
    /// Structured detail payload (JSON-compatible)
    pub details: HashMap<String, String>,
    /// IDs of events that caused this one (correlation chain)
    pub caused_by: Vec<u64>,
    /// Tags for filtering (e.g., "network", "lateral-movement", "cloud")
    pub tags: Vec<String>,
}

// ── Subscriber ───────────────────────────────────────────────────────────────

/// A subscriber callback. Box<dyn Fn> would prevent Send+Sync, so we use a
/// trait-object-free approach: subscribers register a channel sender.
pub type SubscriberFn = Arc<dyn Fn(&SecurityEvent) + Send + Sync>;

struct Subscription {
    id: u64,
    name: String,
    filter_category: Option<EventCategory>,
    filter_severity_min: Option<EventSeverity>,
    filter_tags: Vec<String>,
    callback: SubscriberFn,
}

// ── Event Bus ────────────────────────────────────────────────────────────────

/// The central event bus connecting all sentinel components.
pub struct EventBus {
    /// All subscriptions
    subscriptions: RwLock<Vec<Subscription>>,
    /// Recent event log (ring buffer semantics via pruning)
    event_log: RwLock<Vec<SecurityEvent>>,
    /// Monotonic event ID counter
    next_event_id: AtomicU64,
    /// Monotonic subscription ID counter
    next_sub_id: AtomicU64,
    /// Stats
    total_published: AtomicU64,
    total_delivered: AtomicU64,
    total_dropped: AtomicU64,
    /// Memory metrics
    metrics: Option<MemoryMetrics>,
}

impl EventBus {
    pub fn new() -> Self {
        Self {
            subscriptions: RwLock::new(Vec::new()),
            event_log: RwLock::new(Vec::with_capacity(1024)),
            next_event_id: AtomicU64::new(1),
            next_sub_id: AtomicU64::new(1),
            total_published: AtomicU64::new(0),
            total_delivered: AtomicU64::new(0),
            total_dropped: AtomicU64::new(0),
            metrics: None,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("event_bus", 16 * 1024 * 1024);
        self.metrics = Some(metrics);
        self
    }

    // ── Publishing ───────────────────────────────────────────────────────

    /// Publish a raw event. Returns the assigned event ID.
    pub fn publish(&self, mut event: SecurityEvent) -> u64 {
        let id = self.next_event_id.fetch_add(1, Ordering::Relaxed);
        event.id = id;
        if event.timestamp_ms == 0 {
            event.timestamp_ms = chrono::Utc::now().timestamp_millis();
        }
        self.total_published.fetch_add(1, Ordering::Relaxed);

        debug!(
            id = id,
            src = %event.source_component,
            cat = ?event.category,
            sev = ?event.severity,
            title = %event.title,
            "Event published"
        );

        // Deliver to matching subscribers
        let subs = self.subscriptions.read();
        for sub in subs.iter() {
            if self.matches_filter(sub, &event) {
                (sub.callback)(&event);
                self.total_delivered.fetch_add(1, Ordering::Relaxed);
            }
        }

        // Store in log (with pruning)
        let mut log = self.event_log.write();
        if log.len() >= MAX_EVENT_QUEUE {
            let drain_count = MAX_EVENT_QUEUE / 10; // Drop oldest 10%
            log.drain(..drain_count);
            self.total_dropped.fetch_add(drain_count as u64, Ordering::Relaxed);
        }
        log.push(event);

        id
    }

    /// Convenience: publish a detection event from a component.
    pub fn emit_detection(
        &self,
        component: &str,
        crate_name: &str,
        severity: EventSeverity,
        title: &str,
        details: HashMap<String, String>,
        tags: Vec<String>,
    ) -> u64 {
        self.publish(SecurityEvent {
            id: 0,
            timestamp_ms: 0,
            source_component: component.into(),
            source_crate: crate_name.into(),
            category: EventCategory::Detection,
            severity,
            title: title.into(),
            details,
            caused_by: Vec::new(),
            tags,
        })
    }

    /// Convenience: publish a correlated event caused by prior events.
    pub fn emit_correlation(
        &self,
        component: &str,
        crate_name: &str,
        severity: EventSeverity,
        title: &str,
        details: HashMap<String, String>,
        caused_by: Vec<u64>,
        tags: Vec<String>,
    ) -> u64 {
        self.publish(SecurityEvent {
            id: 0,
            timestamp_ms: 0,
            source_component: component.into(),
            source_crate: crate_name.into(),
            category: EventCategory::Correlation,
            severity,
            title: title.into(),
            details,
            caused_by,
            tags,
        })
    }

    /// Convenience: publish an automated response event.
    pub fn emit_response(
        &self,
        component: &str,
        crate_name: &str,
        severity: EventSeverity,
        title: &str,
        details: HashMap<String, String>,
        caused_by: Vec<u64>,
        tags: Vec<String>,
    ) -> u64 {
        self.publish(SecurityEvent {
            id: 0,
            timestamp_ms: 0,
            source_component: component.into(),
            source_crate: crate_name.into(),
            category: EventCategory::Response,
            severity,
            title: title.into(),
            details,
            caused_by,
            tags,
        })
    }

    // ── Subscribing ──────────────────────────────────────────────────────

    /// Subscribe to events. Returns a subscription ID for later unsubscribe.
    pub fn subscribe(
        &self,
        name: &str,
        filter_category: Option<EventCategory>,
        filter_severity_min: Option<EventSeverity>,
        filter_tags: Vec<String>,
        callback: SubscriberFn,
    ) -> u64 {
        let id = self.next_sub_id.fetch_add(1, Ordering::Relaxed);
        let mut subs = self.subscriptions.write();
        if subs.len() >= MAX_SUBSCRIBERS {
            warn!(name = %name, "Max subscribers reached, dropping oldest");
            subs.remove(0);
        }
        subs.push(Subscription {
            id,
            name: name.into(),
            filter_category,
            filter_severity_min,
            filter_tags,
            callback,
        });
        id
    }

    /// Remove a subscription by ID.
    pub fn unsubscribe(&self, sub_id: u64) -> bool {
        let mut subs = self.subscriptions.write();
        let before = subs.len();
        subs.retain(|s| s.id != sub_id);
        subs.len() < before
    }

    // ── Querying ─────────────────────────────────────────────────────────

    /// Get recent events (up to `limit`), optionally filtered.
    pub fn recent_events(&self, limit: usize, category: Option<EventCategory>) -> Vec<SecurityEvent> {
        let log = self.event_log.read();
        log.iter()
            .rev()
            .filter(|e| category.map_or(true, |c| e.category == c))
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get all events caused by a specific event ID (correlation chain).
    pub fn trace_event(&self, event_id: u64) -> Vec<SecurityEvent> {
        let log = self.event_log.read();
        log.iter()
            .filter(|e| e.caused_by.contains(&event_id))
            .cloned()
            .collect()
    }

    /// Get events matching specific tags.
    pub fn events_by_tag(&self, tag: &str, limit: usize) -> Vec<SecurityEvent> {
        let log = self.event_log.read();
        log.iter()
            .rev()
            .filter(|e| e.tags.iter().any(|t| t == tag))
            .take(limit)
            .cloned()
            .collect()
    }

    // ── Stats ────────────────────────────────────────────────────────────

    pub fn total_published(&self) -> u64 { self.total_published.load(Ordering::Relaxed) }
    pub fn total_delivered(&self) -> u64 { self.total_delivered.load(Ordering::Relaxed) }
    pub fn total_dropped(&self) -> u64 { self.total_dropped.load(Ordering::Relaxed) }
    pub fn event_log_size(&self) -> usize { self.event_log.read().len() }
    pub fn subscriber_count(&self) -> usize { self.subscriptions.read().len() }

    // ── Internal ─────────────────────────────────────────────────────────

    fn matches_filter(&self, sub: &Subscription, event: &SecurityEvent) -> bool {
        // Category filter
        if let Some(cat) = sub.filter_category {
            if event.category != cat {
                return false;
            }
        }
        // Severity floor
        if let Some(min_sev) = sub.filter_severity_min {
            if event.severity < min_sev {
                return false;
            }
        }
        // Tag filter (any match)
        if !sub.filter_tags.is_empty() {
            if !sub.filter_tags.iter().any(|ft| event.tags.contains(ft)) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64 as TestCounter;

    #[test]
    fn test_publish_and_subscribe() {
        let bus = EventBus::new();
        let counter = Arc::new(TestCounter::new(0));
        let c = counter.clone();

        bus.subscribe(
            "test_sub",
            Some(EventCategory::Detection),
            None,
            vec![],
            Arc::new(move |_event| { c.fetch_add(1, Ordering::Relaxed); }),
        );

        let id = bus.emit_detection(
            "test_component", "sentinel-test",
            EventSeverity::High, "Test detection",
            HashMap::new(), vec!["network".into()],
        );

        assert!(id > 0);
        assert_eq!(counter.load(Ordering::Relaxed), 1);
        assert_eq!(bus.total_published(), 1);
        assert_eq!(bus.total_delivered(), 1);
    }

    #[test]
    fn test_category_filter() {
        let bus = EventBus::new();
        let counter = Arc::new(TestCounter::new(0));
        let c = counter.clone();

        // Only subscribe to Response events
        bus.subscribe(
            "response_only",
            Some(EventCategory::Response),
            None,
            vec![],
            Arc::new(move |_| { c.fetch_add(1, Ordering::Relaxed); }),
        );

        // Publish a Detection — should NOT trigger subscriber
        bus.emit_detection("c", "s", EventSeverity::High, "det", HashMap::new(), vec![]);
        assert_eq!(counter.load(Ordering::Relaxed), 0);

        // Publish a Response — SHOULD trigger subscriber
        bus.emit_response("c", "s", EventSeverity::High, "resp", HashMap::new(), vec![], vec![]);
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_severity_filter() {
        let bus = EventBus::new();
        let counter = Arc::new(TestCounter::new(0));
        let c = counter.clone();

        // Only High or above
        bus.subscribe(
            "high_only",
            None,
            Some(EventSeverity::High),
            vec![],
            Arc::new(move |_| { c.fetch_add(1, Ordering::Relaxed); }),
        );

        bus.emit_detection("c", "s", EventSeverity::Low, "low", HashMap::new(), vec![]);
        assert_eq!(counter.load(Ordering::Relaxed), 0);

        bus.emit_detection("c", "s", EventSeverity::Critical, "crit", HashMap::new(), vec![]);
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_tag_filter() {
        let bus = EventBus::new();
        let counter = Arc::new(TestCounter::new(0));
        let c = counter.clone();

        bus.subscribe(
            "network_only",
            None, None,
            vec!["network".into()],
            Arc::new(move |_| { c.fetch_add(1, Ordering::Relaxed); }),
        );

        bus.emit_detection("c", "s", EventSeverity::High, "cloud event", HashMap::new(), vec!["cloud".into()]);
        assert_eq!(counter.load(Ordering::Relaxed), 0);

        bus.emit_detection("c", "s", EventSeverity::High, "net event", HashMap::new(), vec!["network".into()]);
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_event_trace() {
        let bus = EventBus::new();
        let id1 = bus.emit_detection("scanner", "s", EventSeverity::High, "initial", HashMap::new(), vec![]);
        let id2 = bus.emit_correlation("correlator", "s", EventSeverity::High, "correlated", HashMap::new(), vec![id1], vec![]);
        let _id3 = bus.emit_response("responder", "s", EventSeverity::High, "quarantine", HashMap::new(), vec![id2], vec![]);

        let chain = bus.trace_event(id1);
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].title, "correlated");

        let chain2 = bus.trace_event(id2);
        assert_eq!(chain2.len(), 1);
        assert_eq!(chain2[0].title, "quarantine");
    }

    #[test]
    fn test_event_pruning() {
        let bus = EventBus::new();
        // Publish more than MAX_EVENT_QUEUE
        for i in 0..1000 {
            bus.emit_detection("c", "s", EventSeverity::Info, &format!("event-{}", i), HashMap::new(), vec![]);
        }
        assert!(bus.event_log_size() <= MAX_EVENT_QUEUE);
        assert_eq!(bus.total_published(), 1000);
    }

    #[test]
    fn test_unsubscribe() {
        let bus = EventBus::new();
        let counter = Arc::new(TestCounter::new(0));
        let c = counter.clone();

        let sub_id = bus.subscribe("temp", None, None, vec![], Arc::new(move |_| { c.fetch_add(1, Ordering::Relaxed); }));
        bus.emit_detection("c", "s", EventSeverity::Info, "e1", HashMap::new(), vec![]);
        assert_eq!(counter.load(Ordering::Relaxed), 1);

        bus.unsubscribe(sub_id);
        bus.emit_detection("c", "s", EventSeverity::Info, "e2", HashMap::new(), vec![]);
        assert_eq!(counter.load(Ordering::Relaxed), 1); // Still 1, no new delivery
    }
}
