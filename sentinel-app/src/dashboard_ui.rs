use crate::components::SecurityStack;
use axum::{extract::State, response::Html, routing::get, Json, Router};
use std::sync::Arc;
use serde_json::json;

pub async fn start_dashboard(stack: Arc<SecurityStack>, bind: &str) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/", get(serve_html))
        .route("/api/status", get(api_status))
        .route("/api/alerts", get(api_alerts))
        .route("/api/metrics", get(api_metrics))
        .route("/api/ai-security", get(api_ai_security))
        .route("/api/modules", get(api_modules))
        .with_state(stack);

    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn serve_html() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

async fn api_status(State(stack): State<Arc<SecurityStack>>) -> Json<serde_json::Value> {
    let domains = stack.domain_statuses();
    let enabled = domains.iter().filter(|d| d.enabled).count();
    let total_modules: usize = domains.iter().map(|d| d.module_count).sum();
    Json(json!({
        "domains": domains,
        "enabled_domains": enabled,
        "total_modules": total_modules,
    }))
}

async fn api_alerts(State(stack): State<Arc<SecurityStack>>) -> Json<serde_json::Value> {
    let alerts = stack.collect_alerts();
    let critical = alerts.iter().filter(|a| a.severity == "Critical").count();
    let high = alerts.iter().filter(|a| a.severity == "High").count();
    Json(json!({
        "alerts": alerts,
        "total": alerts.len(),
        "critical": critical,
        "high": high,
    }))
}

async fn api_metrics(State(stack): State<Arc<SecurityStack>>) -> Json<serde_json::Value> {
    let report = stack.metrics.report();
    Json(json!({
        "total_budget": report.total_budget,
        "total_used": report.total_used,
        "utilization_percent": report.utilization_percent,
        "components": report.components,
    }))
}

async fn api_ai_security(State(stack): State<Arc<SecurityStack>>) -> Json<serde_json::Value> {
    let ai_alerts = stack.collect_alerts().into_iter()
        .filter(|a| a.domain == "ai").collect::<Vec<_>>();
    let ai_modules: Vec<&str> = vec![
        // Core AI monitoring
        "Shadow AI Detector", "API Key Monitor", "Prompt Guard", "Model Scanner",
        "Output Filter", "Local Sandbox", "Data Poisoning Detector",
        // Pre-inference defense
        "Semantic Firewall", "Indirect Injection Scanner", "Multi-Turn Tracker",
        "Token Smuggling Detector", "Context Window Stuffing Guard",
        "Instruction Hierarchy Enforcer", "Capability Probe Detector",
        // Agent runtime security
        "Tool Call Validator", "Tool Integrity Verifier", "Agent Action Logger",
        "Agent Permission Boundary", "Agent Network Fence", "Agent Behavior Baseline",
        "Agent Session Recorder", "Agent Cost Monitor", "Agent Identity Attestation",
        "Clipboard Exfil Detector", "Multi-Agent Conflict Detector",
        "Delegation Chain Auditor", "Cross-Plugin Data Fence",
        "Autonomous Agent Containment",
        // Post-inference & output
        "Output Watermarker", "Hallucination Detector", "Conversation State Integrity",
        // Continuous monitoring
        "RAG Poisoning Detector", "MCP Protocol Security", "Reasoning Trace Auditor",
        "Memory Poisoning Guard", "Sleeper Agent Detector", "Goal Drift Monitor",
        "Agentic Loop Detector", "Human-in-the-Loop Enforcer",
        "Model Extraction Guard", "Adversarial Input Detector",
        "AI Supply Chain Attestation", "Security Pipeline",
        // Tier 1 — Critical AI defense
        "System Prompt Guardian", "Multimodal Injection Scanner",
        "Jailbreak Classifier", "Training Data Extraction Guard",
        "Embedding Space Monitor",
        // Tier 2 — Important AI defense
        "Synthetic Content Detector", "Fine-Tuning Attack Detector",
        "Reward Hacking Detector", "Model Drift Sentinel",
    ];
    let world_first = vec![
        json!({"name": "RAG Poisoning Detector", "categories": 12, "description": "Detects poisoned documents in retrieval-augmented generation pipelines"}),
        json!({"name": "MCP Protocol Security", "categories": 15, "description": "Validates Model Context Protocol and Agent-to-Agent protocol messages"}),
        json!({"name": "Reasoning Trace Auditor", "categories": 8, "description": "Detects think-act divergence in AI agent chain-of-thought"}),
        json!({"name": "Jailbreak Classifier", "categories": 11, "description": "Multi-technique jailbreak detection with φ-weighted escalation scoring"}),
        json!({"name": "System Prompt Guardian", "categories": 9, "description": "Detects system prompt extraction and leakage attempts across sessions"}),
        json!({"name": "Multimodal Injection Scanner", "categories": 7, "description": "Scans images, audio, and documents for embedded prompt injections"}),
        json!({"name": "Embedding Space Monitor", "categories": 6, "description": "Detects adversarial perturbations and drift in embedding spaces"}),
    ];
    Json(json!({
        "total_modules": ai_modules.len(),
        "modules": ai_modules,
        "alerts": ai_alerts,
        "alert_count": ai_alerts.len(),
        "world_first_modules": world_first,
    }))
}

async fn api_modules(State(stack): State<Arc<SecurityStack>>) -> Json<serde_json::Value> {
    let modules: Vec<serde_json::Value> = stack.components.iter().map(|c| {
        json!({"domain": c.domain, "name": c.name, "alert_count": (c.get_alerts)().len()})
    }).collect();
    Json(json!({"modules": modules, "total": modules.len()}))
}

const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Nexus Sentinel — Security Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0a0e17;--card:#111827;--border:#1e293b;--text:#e2e8f0;--dim:#64748b;
--green:#10b981;--red:#ef4444;--amber:#f59e0b;--blue:#3b82f6;--purple:#8b5cf6;--cyan:#06b6d4}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,monospace;background:var(--bg);color:var(--text);min-height:100vh}
header{background:linear-gradient(135deg,#0f172a,#1e1b4b);border-bottom:1px solid var(--border);padding:16px 24px;display:flex;align-items:center;justify-content:space-between}
header h1{font-size:20px;font-weight:700;background:linear-gradient(90deg,var(--cyan),var(--purple));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
header .meta{font-size:12px;color:var(--dim)}
.stats-bar{display:flex;gap:16px;padding:16px 24px;border-bottom:1px solid var(--border);background:#0d1117}
.stat{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:12px 20px;flex:1;text-align:center}
.stat .val{font-size:28px;font-weight:700;color:var(--cyan)}
.stat .label{font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:1px;margin-top:4px}
.stat.critical .val{color:var(--red)}
.stat.warning .val{color:var(--amber)}
main{display:grid;grid-template-columns:1fr 1fr;gap:16px;padding:16px 24px}
@media(max-width:900px){main{grid-template-columns:1fr}}
.panel{background:var(--card);border:1px solid var(--border);border-radius:8px;overflow:hidden}
.panel-header{padding:12px 16px;border-bottom:1px solid var(--border);font-size:13px;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:var(--dim);display:flex;justify-content:space-between}
.panel-body{padding:12px 16px;max-height:400px;overflow-y:auto}
.domain-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px}
.domain-card{background:#0a0e17;border:1px solid var(--border);border-radius:6px;padding:10px 12px;position:relative;overflow:hidden}
.domain-card.active{border-color:var(--green)}
.domain-card.active::before{content:'';position:absolute;top:0;left:0;width:3px;height:100%;background:var(--green)}
.domain-card.inactive{opacity:0.4}
.domain-card .name{font-size:13px;font-weight:600;margin-bottom:2px}
.domain-card .modules{font-size:11px;color:var(--dim)}
.domain-card .badge{display:inline-block;font-size:10px;padding:1px 6px;border-radius:3px;margin-left:6px}
.badge-on{background:rgba(16,185,129,0.2);color:var(--green)}
.badge-off{background:rgba(100,116,139,0.2);color:var(--dim)}
.alert-item{padding:8px 0;border-bottom:1px solid #1a1f2e;font-size:12px;display:flex;gap:10px;align-items:flex-start}
.alert-item:last-child{border-bottom:none}
.alert-sev{font-size:10px;font-weight:700;padding:2px 6px;border-radius:3px;min-width:60px;text-align:center;flex-shrink:0}
.sev-Critical{background:rgba(239,68,68,0.2);color:var(--red)}
.sev-High{background:rgba(245,158,11,0.2);color:var(--amber)}
.sev-Medium{background:rgba(59,130,246,0.2);color:var(--blue)}
.sev-Low{background:rgba(100,116,139,0.2);color:var(--dim)}
.alert-body .title{font-weight:600;color:var(--text)}
.alert-body .details{color:var(--dim);margin-top:2px;word-break:break-all}
.alert-body .meta{color:#475569;font-size:10px;margin-top:2px}
.mem-bar{background:#1a1f2e;border-radius:4px;height:20px;margin:6px 0;overflow:hidden}
.mem-fill{height:100%;border-radius:4px;transition:width 0.5s}
.mem-label{display:flex;justify-content:space-between;font-size:11px;color:var(--dim)}
.mem-component{padding:4px 0;font-size:12px;display:flex;justify-content:space-between;border-bottom:1px solid #1a1f2e}
.no-data{color:var(--dim);font-size:13px;text-align:center;padding:20px}
footer{text-align:center;padding:16px;font-size:11px;color:#334155;border-top:1px solid var(--border)}
</style>
</head>
<body>
<header>
<div><h1>NEXUS SENTINEL</h1><div class="meta">Comprehensive Security Suite</div></div>
<div class="meta" id="clock"></div>
</header>
<div class="stats-bar">
<div class="stat" id="stat-domains"><div class="val">-</div><div class="label">Security Domains</div></div>
<div class="stat" id="stat-modules"><div class="val">-</div><div class="label">Active Modules</div></div>
<div class="stat critical" id="stat-critical"><div class="val">0</div><div class="label">Critical Alerts</div></div>
<div class="stat warning" id="stat-high"><div class="val">0</div><div class="label">High Alerts</div></div>
<div class="stat" id="stat-memory"><div class="val">-</div><div class="label">Memory Usage</div></div>
</div>
<main>
<div class="panel" style="grid-column:1/-1">
<div class="panel-header"><span>Security Domains</span><span id="domain-count"></span></div>
<div class="panel-body"><div class="domain-grid" id="domain-grid"></div></div>
</div>
<div class="panel" style="grid-column:1/-1">
<div class="panel-header" style="background:linear-gradient(90deg,rgba(139,92,246,0.15),rgba(6,182,212,0.15))"><span style="color:var(--purple)">AI Agent Security — 55 Modules (7 World-First)</span><span id="ai-alert-count"></span></div>
<div class="panel-body" id="ai-panel"><div class="no-data">Loading AI security...</div></div>
</div>
<div class="panel">
<div class="panel-header"><span>Alert Feed</span><span id="alert-total"></span></div>
<div class="panel-body" id="alert-feed"><div class="no-data">Loading alerts...</div></div>
</div>
<div class="panel">
<div class="panel-header"><span>Memory Usage</span></div>
<div class="panel-body" id="mem-panel"><div class="no-data">Loading metrics...</div></div>
</div>
</main>
<footer>Nexus Sentinel — Real-time Security Monitoring — Auto-refresh 5s</footer>
<script>
function fmt(b){if(b>1073741824)return(b/1073741824).toFixed(1)+'GB';if(b>1048576)return(b/1048576).toFixed(1)+'MB';if(b>1024)return(b/1024).toFixed(1)+'KB';return b+'B'}
function age(ts){const d=Math.floor(Date.now()/1000)-ts;if(d<60)return d+'s ago';if(d<3600)return Math.floor(d/60)+'m ago';return Math.floor(d/3600)+'h ago'}

async function refresh(){
  try{
    const[status,alerts,metrics,aiSec]=await Promise.all([
      fetch('/api/status').then(r=>r.json()),
      fetch('/api/alerts').then(r=>r.json()),
      fetch('/api/metrics').then(r=>r.json()),
      fetch('/api/ai-security').then(r=>r.json())
    ]);
    // Stats bar
    document.querySelector('#stat-domains .val').textContent=status.enabled_domains+'/'+status.domains.length;
    document.querySelector('#stat-modules .val').textContent=status.total_modules;
    document.querySelector('#stat-critical .val').textContent=alerts.critical;
    document.querySelector('#stat-high .val').textContent=alerts.high;
    document.querySelector('#stat-memory .val').textContent=metrics.utilization_percent.toFixed(1)+'%';

    // Domain grid
    const grid=document.getElementById('domain-grid');
    grid.innerHTML=status.domains.map(d=>`
      <div class="domain-card ${d.enabled?'active':'inactive'}">
        <div class="name">${d.display_name}<span class="badge ${d.enabled?'badge-on':'badge-off'}">${d.enabled?'ON':'OFF'}</span></div>
        <div class="modules">${d.module_count} module${d.module_count!==1?'s':''}</div>
      </div>`).join('');
    document.getElementById('domain-count').textContent=status.enabled_domains+' active';

    // Alerts
    const feed=document.getElementById('alert-feed');
    if(alerts.alerts.length===0){feed.innerHTML='<div class="no-data">No alerts — system clean</div>';}
    else{feed.innerHTML=alerts.alerts.slice(0,100).map(a=>`
      <div class="alert-item">
        <div class="alert-sev sev-${a.severity}">${a.severity}</div>
        <div class="alert-body">
          <div class="title">${a.title}</div>
          <div class="details">${a.details.substring(0,200)}</div>
          <div class="meta">${a.domain} / ${a.component} — ${age(a.timestamp)}</div>
        </div>
      </div>`).join('');}
    document.getElementById('alert-total').textContent=alerts.total+' total';

    // Memory
    const mp=document.getElementById('mem-panel');
    const pct=metrics.utilization_percent;
    const color=pct>90?'var(--red)':pct>70?'var(--amber)':'var(--green)';
    let html=`<div class="mem-label"><span>Global</span><span>${fmt(metrics.total_used)} / ${fmt(metrics.total_budget)}</span></div>
      <div class="mem-bar"><div class="mem-fill" style="width:${Math.min(pct,100)}%;background:${color}"></div></div>`;
    const comps=Object.entries(metrics.components||{}).sort((a,b)=>b[1].used-a[1].used).slice(0,20);
    comps.forEach(([name,c])=>{html+=`<div class="mem-component"><span>${name}</span><span>${fmt(c.used)} / ${fmt(c.budget)}</span></div>`;});
    mp.innerHTML=html;

    // AI Security panel
    const ap=document.getElementById('ai-panel');
    let ah='<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px;margin-bottom:12px">';
    const wfStyle='border:1px solid var(--purple);background:rgba(139,92,246,0.08)';
    const normalStyle='border:1px solid var(--border);background:#0a0e17';
    const wfNames=new Set((aiSec.world_first_modules||[]).map(w=>w.name));
    (aiSec.modules||[]).forEach(mod=>{
      const isWf=wfNames.has(mod);
      ah+=`<div style="${isWf?wfStyle:normalStyle};border-radius:6px;padding:8px 10px;font-size:12px">`;
      ah+=`<div style="font-weight:600;color:${isWf?'var(--purple)':'var(--text)'}">${isWf?'&#9733; ':''}${mod}</div>`;
      if(isWf){const wf=(aiSec.world_first_modules||[]).find(w=>w.name===mod);if(wf)ah+=`<div style="font-size:10px;color:var(--cyan);margin-top:2px">${wf.categories} detection categories</div><div style="font-size:10px;color:var(--dim);margin-top:1px">${wf.description}</div>`;}
      ah+='</div>';
    });
    ah+='</div>';
    if(aiSec.alert_count>0){ah+=`<div style="font-size:12px;color:var(--amber);margin-top:8px">${aiSec.alert_count} AI security alerts</div>`;}
    else{ah+=`<div style="font-size:12px;color:var(--green);margin-top:8px">No AI security alerts — all agents clean</div>`;}
    ap.innerHTML=ah;
    const aic=document.getElementById('ai-alert-count');
    if(aic)aic.textContent=aiSec.alert_count+' alerts';
  }catch(e){console.error('Refresh error',e)}
}

function updateClock(){document.getElementById('clock').textContent=new Date().toISOString().replace('T',' ').substring(0,19)+' UTC'}
setInterval(updateClock,1000);updateClock();
setInterval(refresh,5000);refresh();
</script>
</body>
</html>"#;
