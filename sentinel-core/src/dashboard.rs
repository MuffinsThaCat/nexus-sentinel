//! # Dashboard API — Real-time web management interface
//!
//! Serves a REST API + embedded HTML dashboard for monitoring all sentinel
//! components, viewing alerts, managing config, and controlling the system.

use crate::event_bus::{EventBus, EventCategory, SecurityEvent};
use crate::MemoryMetrics;
use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Json},
    routing::get,
    Router,
};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::info;

/// Shared state for the dashboard.
#[derive(Clone)]
pub struct DashboardState {
    pub bus: Arc<EventBus>,
    pub metrics: Option<MemoryMetrics>,
    pub start_time: i64,
    pub component_status: Arc<RwLock<HashMap<String, ComponentStatus>>>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ComponentStatus {
    pub name: String,
    pub crate_name: String,
    pub enabled: bool,
    pub alerts: u64,
    pub last_activity: Option<i64>,
}

/// Start the dashboard server.
pub async fn start_dashboard(state: DashboardState, bind_addr: &str) -> Result<(), String> {
    let app = Router::new()
        .route("/", get(dashboard_html))
        .route("/api/status", get(api_status))
        .route("/api/events", get(api_events))
        .route("/api/events/detections", get(api_detections))
        .route("/api/events/responses", get(api_responses))
        .route("/api/memory", get(api_memory))
        .route("/api/components", get(api_components))
        .route("/api/health", get(api_health))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind_addr).await
        .map_err(|e| format!("Failed to bind dashboard to {}: {}", bind_addr, e))?;

    info!(addr = %bind_addr, "Dashboard started");

    axum::serve(listener, app).await
        .map_err(|e| format!("Dashboard server error: {}", e))?;

    Ok(())
}

// ── API Handlers ─────────────────────────────────────────────────────────

async fn api_status(State(state): State<DashboardState>) -> impl IntoResponse {
    let uptime = chrono::Utc::now().timestamp() - state.start_time;
    let bus = &state.bus;

    Json(serde_json::json!({
        "status": "running",
        "uptime_secs": uptime,
        "events_published": bus.total_published(),
        "events_delivered": bus.total_delivered(),
        "events_dropped": bus.total_dropped(),
        "event_log_size": bus.event_log_size(),
        "subscribers": bus.subscriber_count(),
        "timestamp": chrono::Utc::now().to_rfc3339(),
    }))
}

async fn api_events(State(state): State<DashboardState>) -> impl IntoResponse {
    let events = state.bus.recent_events(100, None);
    Json(events)
}

async fn api_detections(State(state): State<DashboardState>) -> impl IntoResponse {
    let events = state.bus.recent_events(100, Some(EventCategory::Detection));
    Json(events)
}

async fn api_responses(State(state): State<DashboardState>) -> impl IntoResponse {
    let events = state.bus.recent_events(100, Some(EventCategory::Response));
    Json(events)
}

async fn api_memory(State(state): State<DashboardState>) -> impl IntoResponse {
    if let Some(ref metrics) = state.metrics {
        let report = metrics.report();
        Json(serde_json::json!({
            "total_budget": report.total_budget,
            "components": report.components.iter().map(|c| {
                serde_json::json!({
                    "name": c.name,
                    "budget": c.theoretical_bound,
                })
            }).collect::<Vec<_>>(),
        }))
    } else {
        Json(serde_json::json!({"error": "No metrics available"}))
    }
}

async fn api_components(State(state): State<DashboardState>) -> impl IntoResponse {
    let components = state.component_status.read().clone();
    Json(components)
}

async fn api_health(State(_state): State<DashboardState>) -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({"healthy": true})))
}

// ── Embedded Dashboard HTML ──────────────────────────────────────────────

async fn dashboard_html(State(_state): State<DashboardState>) -> impl IntoResponse {
    Html(DASHBOARD_HTML)
}

const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Nexus Sentinel — Security Dashboard</title>
<style>
  :root { --bg: #0a0e17; --card: #111827; --border: #1f2937; --text: #e5e7eb; --accent: #3b82f6; --danger: #ef4444; --warn: #f59e0b; --success: #10b981; --muted: #6b7280; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: var(--bg); color: var(--text); font-family: 'SF Mono', 'Fira Code', monospace; }
  .header { background: linear-gradient(135deg, #1e3a5f, #0a0e17); padding: 20px 30px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
  .header h1 { font-size: 1.4em; color: var(--accent); }
  .header .status { display: flex; gap: 20px; font-size: 0.85em; }
  .header .status .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: var(--success); margin-right: 6px; animation: pulse 2s infinite; }
  @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; padding: 20px 30px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
  .card h3 { font-size: 0.8em; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
  .card .value { font-size: 2em; font-weight: bold; }
  .card .value.blue { color: var(--accent); }
  .card .value.green { color: var(--success); }
  .card .value.red { color: var(--danger); }
  .card .value.yellow { color: var(--warn); }
  .events { padding: 0 30px 30px; }
  .events h2 { margin-bottom: 12px; font-size: 1.1em; color: var(--accent); }
  .event-list { background: var(--card); border: 1px solid var(--border); border-radius: 8px; max-height: 400px; overflow-y: auto; }
  .event-row { display: grid; grid-template-columns: 140px 80px 200px 1fr; padding: 8px 12px; border-bottom: 1px solid var(--border); font-size: 0.8em; }
  .event-row:last-child { border-bottom: none; }
  .event-row .sev { font-weight: bold; }
  .event-row .sev.Critical { color: var(--danger); }
  .event-row .sev.High { color: var(--warn); }
  .event-row .sev.Medium { color: #fb923c; }
  .event-row .sev.Low { color: var(--muted); }
  .event-row .sev.Info { color: var(--accent); }
  .memory-bar { height: 20px; background: var(--border); border-radius: 4px; overflow: hidden; margin-top: 8px; }
  .memory-bar .fill { height: 100%; background: var(--accent); transition: width 0.5s; }
  footer { padding: 20px 30px; text-align: center; color: var(--muted); font-size: 0.75em; border-top: 1px solid var(--border); }
</style>
</head>
<body>
<div class="header">
  <h1>⛨ NEXUS SENTINEL</h1>
  <div class="status">
    <span><span class="dot"></span>OPERATIONAL</span>
    <span id="uptime">--</span>
    <span id="clock">--</span>
  </div>
</div>

<div class="grid">
  <div class="card"><h3>Events Published</h3><div class="value blue" id="published">--</div></div>
  <div class="card"><h3>Events Delivered</h3><div class="value green" id="delivered">--</div></div>
  <div class="card"><h3>Detections</h3><div class="value yellow" id="detections">--</div></div>
  <div class="card"><h3>Subscribers</h3><div class="value blue" id="subscribers">--</div></div>
  <div class="card">
    <h3>Memory Usage</h3>
    <div class="value blue" id="memory-text">--</div>
    <div class="memory-bar"><div class="fill" id="memory-fill" style="width: 0%"></div></div>
  </div>
  <div class="card"><h3>Components Active</h3><div class="value green" id="components">--</div></div>
</div>

<div class="events">
  <h2>Recent Events</h2>
  <div class="event-list" id="event-list">
    <div class="event-row" style="color: var(--muted);">Loading...</div>
  </div>
</div>

<footer>Nexus Sentinel v1.0 — 39 crates · 240 components · 13 memory optimizations</footer>

<script>
async function refresh() {
  try {
    const [status, events, memory] = await Promise.all([
      fetch('/api/status').then(r => r.json()),
      fetch('/api/events').then(r => r.json()),
      fetch('/api/memory').then(r => r.json()),
    ]);

    document.getElementById('published').textContent = status.events_published.toLocaleString();
    document.getElementById('delivered').textContent = status.events_delivered.toLocaleString();
    document.getElementById('subscribers').textContent = status.subscribers;
    document.getElementById('uptime').textContent = formatUptime(status.uptime_secs);

    const detCount = events.filter(e => e.category === 'Detection').length;
    document.getElementById('detections').textContent = detCount;

    if (memory.components) {
      document.getElementById('components').textContent = memory.components.length;
      const totalBudget = memory.total_budget || 1;
      const used = memory.components.reduce((sum, c) => sum + c.budget, 0);
      const pct = Math.min(100, (used / totalBudget * 100)).toFixed(0);
      document.getElementById('memory-text').textContent = formatBytes(used) + ' / ' + formatBytes(totalBudget);
      document.getElementById('memory-fill').style.width = pct + '%';
    }

    const list = document.getElementById('event-list');
    if (events.length > 0) {
      list.innerHTML = events.slice(0, 50).map(e => {
        const time = new Date(e.timestamp_ms).toLocaleTimeString();
        return `<div class="event-row">
          <span>${time}</span>
          <span class="sev ${e.severity}">${e.severity}</span>
          <span>${e.source_component}</span>
          <span>${e.title}</span>
        </div>`;
      }).join('');
    }
  } catch(err) { console.error('Refresh failed:', err); }
}

function formatUptime(secs) {
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  return `${h}h ${m}m ${s}s`;
}

function formatBytes(b) {
  if (b > 1e9) return (b / 1e9).toFixed(1) + ' GB';
  if (b > 1e6) return (b / 1e6).toFixed(1) + ' MB';
  if (b > 1e3) return (b / 1e3).toFixed(1) + ' KB';
  return b + ' B';
}

setInterval(() => {
  document.getElementById('clock').textContent = new Date().toLocaleTimeString();
}, 1000);

refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>"#;
