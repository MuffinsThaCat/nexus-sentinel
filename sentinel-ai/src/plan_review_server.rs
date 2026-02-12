//! Plan Review Server — production HTTP API for the Plan Review Engine.
//!
//! Standalone sidecar server on `localhost:7700`. Does NOT intercept or modify
//! any IDE, editor, or agent workflow. Agents opt-in by POSTing plans.
//!
//! Endpoints:
//!   POST /v1/review              — Submit a plan for review
//!   POST /v1/approve             — Record a user approval/denial
//!   GET  /v1/stats               — Streaming review statistics
//!   GET  /v1/alerts              — Recent security alerts
//!   GET  /v1/matrix              — Agent×Action risk matrix
//!   GET  /v1/history?limit=N     — Recent review history
//!   GET  /v1/verdict?agent=&goal= — Cached risk verdict lookup
//!   GET  /v1/duplicate/:plan_id  — Check if plan is a duplicate
//!   GET  /v1/patterns            — Learned approval patterns
//!   GET  /v1/health              — Health check
//!   POST /v1/enable              — Enable/disable the engine
//!
//! All responses are JSON. CORS enabled for local development.

use std::sync::Arc;
use std::net::SocketAddr;
use std::path::PathBuf;

use axum::{
    extract::{Path, Query, State},
    http::{StatusCode, Request, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use tower_http::cors::{Any, CorsLayer};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::plan_review_engine::*;

// ── Server State ─────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<PlanReviewEngine>,
    pub state_path: Option<PathBuf>,
    pub api_token: Option<String>,
}

type SharedState = AppState;

// ── Request / Response DTOs ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ApproveRequest {
    pub agent: String,
    pub action: PlanAction,
    pub target: String,
    pub approved: bool,
}

#[derive(Deserialize)]
pub struct EnableRequest {
    pub enabled: bool,
}

#[derive(Deserialize)]
pub struct HistoryQuery {
    pub limit: Option<usize>,
}

#[derive(Deserialize)]
pub struct VerdictQuery {
    pub agent: String,
    pub goal: String,
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub engine_enabled: bool,
    pub total_reviews: u64,
    pub total_critical: u64,
    pub total_denied: u64,
    pub version: &'static str,
}

#[derive(Serialize)]
pub struct ReviewResponse {
    pub review: PlanReview,
    pub is_duplicate: bool,
    pub cached_verdict: Option<RiskLevel>,
}

#[derive(Serialize)]
pub struct EnableResponse {
    pub enabled: bool,
}

#[derive(Serialize)]
pub struct DuplicateResponse {
    pub plan_id: String,
    pub is_duplicate: bool,
}

#[derive(Serialize)]
pub struct ApproveResponse {
    pub recorded: bool,
    pub agent: String,
    pub action: String,
    pub approved: bool,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

// ── Router Construction ──────────────────────────────────────────────────────

pub fn build_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let authed = Router::new()
        .route("/v1/review", post(handle_review))
        .route("/v1/approve", post(handle_approve))
        .route("/v1/enable", post(handle_enable))
        .route("/v1/stats", get(handle_stats))
        .route("/v1/alerts", get(handle_alerts))
        .route("/v1/matrix", get(handle_matrix))
        .route("/v1/history", get(handle_history))
        .route("/v1/verdict", get(handle_verdict))
        .route("/v1/duplicate/:plan_id", get(handle_duplicate))
        .route("/v1/patterns", get(handle_patterns))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

    let public = Router::new()
        .route("/v1/health", get(handle_health))
        .route("/v1/metrics", get(handle_metrics));

    authed.merge(public)
        .layer(cors)
        .with_state(state)
}

// ── Auth Middleware ──────────────────────────────────────────────────────────

async fn auth_middleware(
    State(state): State<SharedState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if let Some(ref expected) = state.api_token {
        let auth_header = req.headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());

        match auth_header {
            Some(val) if val.strip_prefix("Bearer ").map_or(false, |t| t == expected) => {},
            _ => {
                warn!("Unauthorized request rejected");
                return (StatusCode::UNAUTHORIZED, Json(ErrorResponse {
                    error: "Invalid or missing Bearer token".into(),
                })).into_response();
            }
        }
    }
    next.run(req).await
}

/// Server configuration.
pub struct ServerConfig {
    pub addr: SocketAddr,
    pub state_path: Option<PathBuf>,
    pub api_token: Option<String>,
}

/// Start the Plan Review Server.
/// This is a long-running future — call from `#[tokio::main]`.
pub async fn serve(engine: PlanReviewEngine, config: ServerConfig) -> std::io::Result<()> {
    let engine = Arc::new(engine);

    // Load persisted state if available
    if let Some(ref path) = config.state_path {
        if let Err(e) = engine.load_state(path) {
            warn!(%e, "Failed to load persisted state, starting fresh");
        }
    }

    let state = AppState {
        engine,
        state_path: config.state_path,
        api_token: config.api_token.clone(),
    };
    let app = build_router(state);

    let auth_status = if config.api_token.is_some() { "enabled" } else { "disabled (open access)" };
    info!(addr = %config.addr, auth = auth_status, "Plan Review Server starting");
    info!("  POST /v1/review    — submit a plan for security review");
    info!("  POST /v1/approve   — record user approval/denial");
    info!("  GET  /v1/stats     — streaming review statistics");
    info!("  GET  /v1/alerts    — security alerts");
    info!("  GET  /v1/matrix    — agent×action risk matrix");
    info!("  GET  /v1/history   — recent reviews");
    info!("  GET  /v1/verdict   — cached risk verdict lookup");
    info!("  GET  /v1/patterns  — learned approval patterns");
    info!("  GET  /v1/health    — health check (public)");
    info!("  GET  /v1/metrics   — prometheus metrics (public)");

    let listener = tokio::net::TcpListener::bind(config.addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// ── Handlers ─────────────────────────────────────────────────────────────────

async fn handle_review(
    State(state): State<SharedState>,
    Json(plan): Json<AgentPlan>,
) -> impl IntoResponse {
    let cached = state.engine.cached_verdict(&plan.agent_name, &plan.stated_goal);
    let review = state.engine.review_plan(&plan);
    let is_dup = state.engine.is_duplicate_plan(&plan.plan_id);

    // Auto-save after each review
    auto_save(&state);

    (StatusCode::OK, Json(ReviewResponse {
        review,
        is_duplicate: is_dup,
        cached_verdict: cached,
    }))
}

async fn handle_approve(
    State(state): State<SharedState>,
    Json(req): Json<ApproveRequest>,
) -> impl IntoResponse {
    state.engine.record_approval(&req.agent, req.action, &req.target, req.approved);

    // Auto-save after approval changes
    auto_save(&state);

    (StatusCode::OK, Json(ApproveResponse {
        recorded: true,
        agent: req.agent,
        action: format!("{:?}", req.action),
        approved: req.approved,
    }))
}

async fn handle_enable(
    State(state): State<SharedState>,
    Json(req): Json<EnableRequest>,
) -> impl IntoResponse {
    state.engine.set_enabled(req.enabled);
    auto_save(&state);
    info!(enabled = req.enabled, "Engine enabled state changed");
    (StatusCode::OK, Json(EnableResponse { enabled: req.enabled }))
}

async fn handle_stats(
    State(state): State<SharedState>,
) -> impl IntoResponse {
    (StatusCode::OK, Json(state.engine.review_statistics()))
}

async fn handle_alerts(
    State(state): State<SharedState>,
) -> impl IntoResponse {
    (StatusCode::OK, Json(state.engine.alerts()))
}

async fn handle_matrix(
    State(state): State<SharedState>,
) -> impl IntoResponse {
    let entries = state.engine.risk_matrix_entries();
    let matrix: Vec<serde_json::Value> = entries.iter().map(|(agent, action, count)| {
        serde_json::json!({
            "agent": agent,
            "action": action,
            "count": count,
        })
    }).collect();
    (StatusCode::OK, Json(matrix))
}

async fn handle_history(
    State(state): State<SharedState>,
    Query(q): Query<HistoryQuery>,
) -> impl IntoResponse {
    let limit = q.limit.unwrap_or(25).min(500);
    (StatusCode::OK, Json(state.engine.recent_reviews(limit)))
}

async fn handle_verdict(
    State(state): State<SharedState>,
    Query(q): Query<VerdictQuery>,
) -> impl IntoResponse {
    match state.engine.cached_verdict(&q.agent, &q.goal) {
        Some(risk) => (StatusCode::OK, Json(serde_json::json!({
            "agent": q.agent,
            "goal": q.goal,
            "cached_risk": risk,
        }))),
        None => (StatusCode::OK, Json(serde_json::json!({
            "agent": q.agent,
            "goal": q.goal,
            "cached_risk": null,
        }))),
    }
}

async fn handle_duplicate(
    State(state): State<SharedState>,
    Path(plan_id): Path<String>,
) -> impl IntoResponse {
    (StatusCode::OK, Json(DuplicateResponse {
        is_duplicate: state.engine.is_duplicate_plan(&plan_id),
        plan_id,
    }))
}

async fn handle_patterns(
    State(state): State<SharedState>,
) -> impl IntoResponse {
    let patterns = state.engine.approval_patterns();
    let out: Vec<serde_json::Value> = patterns.iter().map(|(agent, pattern, count)| {
        serde_json::json!({
            "agent": agent,
            "pattern": pattern,
            "approved_count": count,
        })
    }).collect();
    (StatusCode::OK, Json(out))
}

async fn handle_health(
    State(state): State<SharedState>,
) -> impl IntoResponse {
    (StatusCode::OK, Json(HealthResponse {
        status: if state.engine.is_enabled() { "active" } else { "disabled" },
        engine_enabled: state.engine.is_enabled(),
        total_reviews: state.engine.review_count(),
        total_critical: state.engine.critical_count(),
        total_denied: state.engine.denied_count(),
        version: env!("CARGO_PKG_VERSION"),
    }))
}

async fn handle_metrics(
    State(state): State<SharedState>,
) -> impl IntoResponse {
    let e = &state.engine;
    let body = format!(
        "# HELP plan_reviews_total Total plans reviewed\n\
         # TYPE plan_reviews_total counter\n\
         plan_reviews_total {}\n\
         # HELP plan_critical_total Total critical risk plans\n\
         # TYPE plan_critical_total counter\n\
         plan_critical_total {}\n\
         # HELP plan_denied_total Total denied plans\n\
         # TYPE plan_denied_total counter\n\
         plan_denied_total {}\n\
         # HELP plan_engine_enabled Whether the engine is active\n\
         # TYPE plan_engine_enabled gauge\n\
         plan_engine_enabled {}\n\
         # HELP plan_risk_checkpoints Total risk trend checkpoints\n\
         # TYPE plan_risk_checkpoints gauge\n\
         plan_risk_checkpoints {}\n",
        e.review_count(),
        e.critical_count(),
        e.denied_count(),
        if e.is_enabled() { 1 } else { 0 },
        e.risk_checkpoint_count(),
    );
    (StatusCode::OK, [(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body)
}

// ── Auto-Save Helper ────────────────────────────────────────────────────────

fn auto_save(state: &AppState) {
    if let Some(ref path) = state.state_path {
        if let Err(e) = state.engine.save_state(path) {
            warn!(%e, "Failed to auto-save state");
        }
    }
}
