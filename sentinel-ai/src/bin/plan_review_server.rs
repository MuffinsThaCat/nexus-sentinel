//! Plan Review Server — standalone binary.
//!
//! Usage:
//!   cargo run --bin plan-review-server
//!   cargo run --bin plan-review-server -- --port 7700
//!
//! The server runs on localhost:7700 by default and does NOT interfere
//! with any IDE, editor, or agent workflow. Agents opt-in by POSTing plans.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use sentinel_ai::plan_review_engine::PlanReviewEngine;
use sentinel_ai::plan_review_server::{self, ServerConfig};

#[derive(Parser)]
#[command(name = "plan-review-server")]
#[command(about = "AI Agent Plan Review Server — pre-flight security for AI agent actions")]
struct Cli {
    /// Port to listen on
    #[arg(short, long, default_value = "7700")]
    port: u16,

    /// Bind address
    #[arg(short, long, default_value = "127.0.0.1")]
    bind: String,

    /// Directory to persist engine state (approval memory, counters).
    /// If omitted, state is ephemeral (lost on restart).
    #[arg(long, env = "PLAN_REVIEW_STATE_DIR")]
    state_dir: Option<PathBuf>,

    /// Bearer token for API authentication.
    /// If omitted, API is open (localhost-only recommended).
    #[arg(long, env = "PLAN_REVIEW_TOKEN")]
    token: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let addr: SocketAddr = format!("{}:{}", cli.bind, cli.port).parse()?;

    let state_path = cli.state_dir.map(|d| d.join("plan_review_state.json"));
    let auth_status = if cli.token.is_some() { "Bearer token" } else { "OPEN (localhost only)" };
    let persist_status = state_path.as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "ephemeral (lost on restart)".into());

    let engine = PlanReviewEngine::new();

    eprintln!();
    eprintln!("  ╔══════════════════════════════════════════════════╗");
    eprintln!("  ║   Plan Review Server v{}                    ║", env!("CARGO_PKG_VERSION"));
    eprintln!("  ║   AI Agent Pre-Flight Security Gate              ║");
    eprintln!("  ╠══════════════════════════════════════════════════╣");
    eprintln!("  ║   http://{:39}║", addr);
    eprintln!("  ║   Auth: {:41}║", auth_status);
    eprintln!("  ║   State: {:40}║", &persist_status[..persist_status.len().min(40)]);
    eprintln!("  ╠══════════════════════════════════════════════════╣");
    eprintln!("  ║   POST /v1/review   — review an agent plan      ║");
    eprintln!("  ║   POST /v1/approve  — record approval/denial    ║");
    eprintln!("  ║   GET  /v1/health   — health check  (public)    ║");
    eprintln!("  ║   GET  /v1/metrics  — prometheus     (public)    ║");
    eprintln!("  ║   GET  /v1/stats    — review statistics         ║");
    eprintln!("  ║   GET  /v1/alerts   — security alerts           ║");
    eprintln!("  ╚══════════════════════════════════════════════════╝");
    eprintln!();

    let config = ServerConfig {
        addr,
        state_path,
        api_token: cli.token,
    };

    plan_review_server::serve(engine, config).await?;
    Ok(())
}
