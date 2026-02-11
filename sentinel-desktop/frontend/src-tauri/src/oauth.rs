use serde::{Serialize, Deserialize};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::auth::{UserStore, AuthResult};
use crate::config::SentinelConfig;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum OAuthProvider {
    Google,
    GitHub,
}

// ── Local Callback Server ────────────────────────────────────────────────────
// The server handles the full OAuth flow (token exchange, user info).
// It redirects the user's browser back to us with ?provider=...&email=...&name=...

struct OAuthResult {
    email: String,
    name: String,
    provider: String,
}

async fn wait_for_oauth_redirect(port: u16) -> Option<OAuthResult> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await.ok()?;
    let (mut stream, _) = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        listener.accept(),
    ).await.ok()?.ok()?;

    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.ok()?;
    let request = String::from_utf8_lossy(&buf[..n]);

    // Parse query params from GET /?provider=...&email=...&name=...
    let query = request
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .split('?')
        .nth(1)?
        .to_string();

    let params: std::collections::HashMap<String, String> = query
        .split('&')
        .filter_map(|p| {
            let mut parts = p.splitn(2, '=');
            Some((parts.next()?.to_string(), urldecode(parts.next()?)))
        })
        .collect();

    let email = params.get("email")?.clone();
    let name = params.get("name").cloned().unwrap_or_default();
    let provider = params.get("provider").cloned().unwrap_or_default();

    // Send success response to browser
    let html = r#"<!DOCTYPE html><html><body style="background:#0a0a0f;color:#fff;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;margin:0">
<div style="text-align:center"><h1 style="color:#00e5ff">&#10003; Signed In</h1><p style="color:#666">You can close this tab and return to Beaver Warrior.</p></div>
</body></html>"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        html.len(), html
    );
    let _ = stream.write_all(response.as_bytes()).await;

    if email.is_empty() {
        return None;
    }

    Some(OAuthResult { email, name, provider })
}

fn urldecode(s: &str) -> String {
    let mut result = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&s[i+1..i+3], 16) {
                result.push(byte);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            result.push(b' ');
        } else {
            result.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8(result).unwrap_or_default()
}

fn find_open_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

// ── Server-Side OAuth ────────────────────────────────────────────────────────
// Desktop opens browser → server handles OAuth → server redirects back to localhost

async fn server_oauth(store: &UserStore, config: &SentinelConfig, provider: OAuthProvider) -> AuthResult {
    let port = find_open_port();

    let provider_path = match provider {
        OAuthProvider::Google => "google",
        OAuthProvider::GitHub => "github",
    };

    let auth_url = format!(
        "{}/auth/{}?callback_port={}",
        config.server_url.trim_end_matches('/'),
        provider_path,
        port,
    );

    if open::that(&auth_url).is_err() {
        return err("Failed to open browser");
    }

    let result = match wait_for_oauth_redirect(port).await {
        Some(r) => r,
        None => return err(&format!("{} sign-in timed out or failed", provider_path)),
    };

    store.oauth_login(&result.email, &if result.name.is_empty() { result.email.clone() } else { result.name }, &result.provider)
}

fn err(msg: &str) -> AuthResult {
    AuthResult {
        success: false,
        message: msg.to_string(),
        state: crate::auth::AuthState { logged_in: false, user: None, session_token: None },
    }
}

// ── Tauri Command ────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn oauth_login(store: tauri::State<'_, Arc<UserStore>>, provider: OAuthProvider) -> Result<AuthResult, String> {
    let config = SentinelConfig::load();
    Ok(server_oauth(&store, &config, provider).await)
}
