use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::Redirect,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use std::path::PathBuf;

// ── Configuration ────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppConfig {
    stripe_webhook_secret: String,
    smtp_host: String,
    smtp_port: u16,
    smtp_username: String,
    smtp_password: String,
    from_email: String,
    from_name: String,
    license_duration_days: u64,
    port: u16,
    server_url: String,
    google_client_id: String,
    google_client_secret: String,
    github_client_id: String,
    github_client_secret: String,
}

impl AppConfig {
    fn from_env() -> Self {
        AppConfig {
            stripe_webhook_secret: env("STRIPE_WEBHOOK_SECRET"),
            smtp_host: env_or("SMTP_HOST", "smtp.gmail.com"),
            smtp_port: env_or("SMTP_PORT", "587").parse().unwrap_or(587),
            smtp_username: env("SMTP_USERNAME"),
            smtp_password: env("SMTP_PASSWORD"),
            from_email: env_or("FROM_EMAIL", "license@nexus-sentinel.com"),
            from_name: env_or("FROM_NAME", "Nexus Sentinel"),
            license_duration_days: env_or("LICENSE_DURATION_DAYS", "365").parse().unwrap_or(365),
            port: env_or("PORT", "3001").parse().unwrap_or(3001),
            server_url: env_or("SERVER_URL", "http://localhost:3001"),
            google_client_id: env("GOOGLE_CLIENT_ID"),
            google_client_secret: env("GOOGLE_CLIENT_SECRET"),
            github_client_id: env("GITHUB_CLIENT_ID"),
            github_client_secret: env("GITHUB_CLIENT_SECRET"),
        }
    }
}

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| {
        tracing::warn!("Environment variable {} not set", key);
        String::new()
    })
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

// ── Same HMAC key as desktop app — MUST match auth.rs ────────────────────────

const LICENSE_HMAC_KEY: &[u8] = b"\xb7\x3a\xf1\x08\x4d\xe9\x52\xc6\x91\x7b\xa0\x3e\xd4\x68\x5f\x2c\xe3\x1a\x9d\x74\x06\xbc\x83\x47\xf5\x62\x0e\xab\xd9\x15\x8c\x70";

// ── License Key Generation (mirrors desktop auth.rs logic exactly) ───────────

fn license_sign(email: &str, tier: &str, expiry_epoch: u64) -> String {
    let payload = format!("{}:{}:{}", email.to_lowercase(), tier, expiry_epoch);
    let mut h = Sha256::new();
    h.update(LICENSE_HMAC_KEY);
    h.update(payload.as_bytes());
    hex::encode(h.finalize())
}

fn generate_license_key(email: &str, tier: &str, expiry_epoch: u64) -> String {
    let email_hash = {
        let mut h = Sha256::new();
        h.update(email.to_lowercase().as_bytes());
        hex::encode(h.finalize())[..12].to_string()
    };
    let sig = license_sign(email, tier, expiry_epoch);
    let sig_short = &sig[..16];
    format!("NS-{}-{}-{}-{}", tier, email_hash, expiry_epoch, sig_short)
}

// ── Server-Side User Store ───────────────────────────────────────────────────

const HASH_ITERATIONS: u32 = 100_000;
const MAX_LOGIN_ATTEMPTS: u32 = 5;
const LOCKOUT_SECS: i64 = 300;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredUser {
    id: String,
    email: String,
    name: String,
    company: Option<String>,
    password_hash: String,
    password_salt: String,
    tier: String,
    created_at: String,
    auth_provider: Option<String>,
    failed_attempts: u32,
    locked_until: Option<String>,
}

fn generate_salt() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn hash_password(password: &str, salt: &str) -> String {
    let mut hash = {
        let mut h = Sha256::new();
        h.update(salt.as_bytes());
        h.update(b":");
        h.update(password.as_bytes());
        h.finalize()
    };
    for _ in 1..HASH_ITERATIONS {
        let mut h = Sha256::new();
        h.update(&hash);
        h.update(salt.as_bytes());
        hash = h.finalize();
    }
    hex::encode(hash)
}

fn verify_password(password: &str, salt: &str, stored_hash: &str) -> bool {
    let computed = hash_password(password, salt);
    if computed.len() != stored_hash.len() { return false; }
    let mut diff = 0u8;
    for (a, b) in computed.bytes().zip(stored_hash.bytes()) {
        diff |= a ^ b;
    }
    diff == 0
}

struct UserStore {
    users: RwLock<HashMap<String, StoredUser>>,
    data_path: PathBuf,
}

impl UserStore {
    fn new() -> Self {
        let data_path = std::env::var("DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./data"));
        std::fs::create_dir_all(&data_path).ok();
        let file = data_path.join("users.json");
        let users: HashMap<String, StoredUser> = if file.exists() {
            std::fs::read_to_string(&file)
                .ok()
                .and_then(|json| serde_json::from_str(&json).ok())
                .unwrap_or_default()
        } else {
            HashMap::new()
        };
        tracing::info!("Loaded {} users from disk", users.len());
        UserStore { users: RwLock::new(users), data_path }
    }

    fn save(&self) {
        let users = self.users.read();
        if let Ok(json) = serde_json::to_string_pretty(&*users) {
            let _ = std::fs::write(self.data_path.join("users.json"), json);
        }
    }

    fn is_locked(u: &StoredUser) -> bool {
        if u.failed_attempts < MAX_LOGIN_ATTEMPTS { return false; }
        if let Some(ref until) = u.locked_until {
            if let Ok(t) = chrono::DateTime::parse_from_rfc3339(until) {
                return chrono::Utc::now() < t;
            }
        }
        false
    }
}

// ── Server State (config + user store) ───────────────────────────────────────

struct ServerState {
    config: AppConfig,
    users: UserStore,
}

// ── Auth Request / Response Types ────────────────────────────────────────────

#[derive(Deserialize)]
struct SignupRequest {
    email: String,
    password: String,
    name: String,
    company: Option<String>,
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct AuthResponse {
    success: bool,
    message: String,
    email: Option<String>,
    name: Option<String>,
    tier: Option<String>,
}

// ── Auth Endpoints ───────────────────────────────────────────────────────────

async fn auth_signup(
    State(state): State<Arc<ServerState>>,
    Json(req): Json<SignupRequest>,
) -> (StatusCode, Json<AuthResponse>) {
    let email = req.email.trim().to_lowercase();

    if email.is_empty() || !email.contains('@') {
        return (StatusCode::BAD_REQUEST, Json(AuthResponse {
            success: false, message: "Invalid email address".into(),
            email: None, name: None, tier: None,
        }));
    }
    if req.password.len() < 8 {
        return (StatusCode::BAD_REQUEST, Json(AuthResponse {
            success: false, message: "Password must be at least 8 characters".into(),
            email: None, name: None, tier: None,
        }));
    }
    if req.name.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(AuthResponse {
            success: false, message: "Name is required".into(),
            email: None, name: None, tier: None,
        }));
    }
    let has_upper = req.password.chars().any(|c| c.is_uppercase());
    let has_digit = req.password.chars().any(|c| c.is_ascii_digit());
    if !has_upper || !has_digit {
        return (StatusCode::BAD_REQUEST, Json(AuthResponse {
            success: false, message: "Password must contain at least one uppercase letter and one digit".into(),
            email: None, name: None, tier: None,
        }));
    }

    let mut users = state.users.users.write();
    if users.contains_key(&email) {
        return (StatusCode::CONFLICT, Json(AuthResponse {
            success: false, message: "An account with this email already exists".into(),
            email: None, name: None, tier: None,
        }));
    }

    let salt = generate_salt();
    let pw_hash = hash_password(&req.password, &salt);
    let name = req.name.trim().to_string();

    let user = StoredUser {
        id: uuid::Uuid::new_v4().to_string(),
        email: email.clone(),
        name: name.clone(),
        company: req.company.as_deref().map(|c| c.trim().to_string()).filter(|c| !c.is_empty()),
        password_hash: pw_hash,
        password_salt: salt,
        tier: "FREE".into(),
        created_at: chrono::Utc::now().to_rfc3339(),
        auth_provider: None,
        failed_attempts: 0,
        locked_until: None,
    };
    users.insert(email.clone(), user);
    drop(users);
    state.users.save();

    tracing::info!("New signup: {} ({})", name, email);

    (StatusCode::OK, Json(AuthResponse {
        success: true, message: "Account created successfully".into(),
        email: Some(email), name: Some(name), tier: Some("FREE".into()),
    }))
}

async fn auth_login(
    State(state): State<Arc<ServerState>>,
    Json(req): Json<LoginRequest>,
) -> (StatusCode, Json<AuthResponse>) {
    let email = req.email.trim().to_lowercase();

    // Check lockout
    {
        let users = state.users.users.read();
        if let Some(user) = users.get(&email) {
            if UserStore::is_locked(user) {
                return (StatusCode::TOO_MANY_REQUESTS, Json(AuthResponse {
                    success: false,
                    message: format!("Account temporarily locked. Try again in {} minutes.", LOCKOUT_SECS / 60),
                    email: None, name: None, tier: None,
                }));
            }
        }
    }

    let mut users = state.users.users.write();
    match users.get_mut(&email) {
        Some(user) => {
            // OAuth users can't login with password
            if user.auth_provider.is_some() {
                return (StatusCode::BAD_REQUEST, Json(AuthResponse {
                    success: false,
                    message: "This account uses social sign-in. Use Google or GitHub instead.".into(),
                    email: None, name: None, tier: None,
                }));
            }

            if !verify_password(&req.password, &user.password_salt, &user.password_hash) {
                user.failed_attempts += 1;
                if user.failed_attempts >= MAX_LOGIN_ATTEMPTS {
                    let lockout = chrono::Utc::now() + chrono::Duration::seconds(LOCKOUT_SECS);
                    user.locked_until = Some(lockout.to_rfc3339());
                }
                let remaining = MAX_LOGIN_ATTEMPTS.saturating_sub(user.failed_attempts);
                drop(users);
                state.users.save();
                let msg = if remaining > 0 {
                    format!("Incorrect password. {} attempt{} remaining.", remaining, if remaining == 1 { "" } else { "s" })
                } else {
                    format!("Account locked for {} minutes due to too many failed attempts.", LOCKOUT_SECS / 60)
                };
                return (StatusCode::UNAUTHORIZED, Json(AuthResponse {
                    success: false, message: msg, email: None, name: None, tier: None,
                }));
            }

            // Success
            user.failed_attempts = 0;
            user.locked_until = None;
            let name = user.name.clone();
            let tier = user.tier.clone();
            drop(users);
            state.users.save();

            tracing::info!("Login success: {}", email);

            (StatusCode::OK, Json(AuthResponse {
                success: true, message: "Logged in successfully".into(),
                email: Some(email), name: Some(name), tier: Some(tier),
            }))
        }
        None => {
            (StatusCode::UNAUTHORIZED, Json(AuthResponse {
                success: false, message: "Invalid email or password".into(),
                email: None, name: None, tier: None,
            }))
        }
    }
}

// ── Stripe Webhook Types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct StripeEvent {
    #[serde(rename = "type")]
    event_type: String,
    data: StripeEventData,
}

#[derive(Debug, Deserialize)]
struct StripeEventData {
    object: StripeSession,
}

#[derive(Debug, Deserialize)]
struct StripeSession {
    customer_email: Option<String>,
    customer_details: Option<CustomerDetails>,
    metadata: Option<serde_json::Value>,
    amount_total: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct CustomerDetails {
    email: Option<String>,
}

impl StripeSession {
    fn email(&self) -> Option<String> {
        self.customer_email.clone()
            .or_else(|| self.customer_details.as_ref()?.email.clone())
    }

    fn tier_from_amount(&self) -> &str {
        match self.amount_total {
            Some(amt) if amt >= 9900 => "ENT",
            Some(amt) if amt >= 2900 => "PRO",
            _ => "FREE",
        }
    }

    fn tier_from_metadata(&self) -> Option<&str> {
        let meta = self.metadata.as_ref()?;
        meta.get("tier")?.as_str()
    }
}

// ── Stripe Webhook Signature Verification ────────────────────────────────────

fn verify_stripe_signature(payload: &[u8], sig_header: &str, secret: &str) -> bool {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    // Parse Stripe-Signature header: t=timestamp,v1=signature
    let mut timestamp = "";
    let mut signatures: Vec<&str> = Vec::new();

    for part in sig_header.split(',') {
        let kv: Vec<&str> = part.splitn(2, '=').collect();
        if kv.len() == 2 {
            match kv[0] {
                "t" => timestamp = kv[1],
                "v1" => signatures.push(kv[1]),
                _ => {}
            }
        }
    }

    if timestamp.is_empty() || signatures.is_empty() {
        return false;
    }

    // Compute expected signature
    let signed_payload = format!("{}.{}", timestamp, String::from_utf8_lossy(payload));
    let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(signed_payload.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());

    // Constant-time comparison
    signatures.iter().any(|sig| {
        if sig.len() != expected.len() { return false; }
        let mut diff = 0u8;
        for (a, b) in sig.bytes().zip(expected.bytes()) {
            diff |= a ^ b;
        }
        diff == 0
    })
}

// ── Email Delivery ───────────────────────────────────────────────────────────

async fn send_license_email(config: &AppConfig, to_email: &str, license_key: &str, tier: &str, expiry: &str) -> Result<(), String> {
    use lettre::{
        message::header::ContentType,
        transport::smtp::authentication::Credentials,
        AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    };

    let tier_name = match tier {
        "PRO" => "Pro",
        "ENT" => "Enterprise",
        _ => "Free",
    };

    let subject = format!("Your Nexus Sentinel {} License Key", tier_name);

    let body = format!(
r#"Thank you for purchasing Nexus Sentinel {}!

Your license key is:

    {}

To activate:
1. Open the Nexus Sentinel desktop app
2. Go to Account → License Key
3. Paste the key above and click "Activate"

License details:
  - Tier: {}
  - Expires: {}
  - Tied to: {}

This key is unique to your account. Do not share it.

If you have any questions, reply to this email.

— The Nexus Sentinel Team
"#,
        tier_name, license_key, tier_name, expiry, to_email
    );

    let email = Message::builder()
        .from(format!("{} <{}>", config.from_name, config.from_email).parse().map_err(|e| format!("From address error: {}", e))?)
        .to(to_email.parse().map_err(|e| format!("To address error: {}", e))?)
        .subject(subject)
        .header(ContentType::TEXT_PLAIN)
        .body(body)
        .map_err(|e| format!("Email build error: {}", e))?;

    let creds = Credentials::new(config.smtp_username.clone(), config.smtp_password.clone());

    let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.smtp_host)
        .map_err(|e| format!("SMTP relay error: {}", e))?
        .port(config.smtp_port)
        .credentials(creds)
        .build();

    mailer.send(email).await
        .map_err(|e| format!("SMTP send error: {}", e))?;

    Ok(())
}

// ── Route Handlers ───────────────────────────────────────────────────────────

async fn health() -> &'static str {
    "Nexus Sentinel License Server — OK"
}

#[derive(Serialize)]
struct WebhookResponse {
    success: bool,
    message: String,
}

async fn stripe_webhook(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> (StatusCode, Json<WebhookResponse>) {
    let config = &state.config;
    // Verify Stripe signature
    let sig = headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !config.stripe_webhook_secret.is_empty()
        && !verify_stripe_signature(&body, sig, &config.stripe_webhook_secret)
    {
        tracing::warn!("Invalid Stripe webhook signature");
        return (
            StatusCode::UNAUTHORIZED,
            Json(WebhookResponse { success: false, message: "Invalid signature".into() }),
        );
    }

    // Parse event
    let event: StripeEvent = match serde_json::from_slice(&body) {
        Ok(e) => e,
        Err(e) => {
            tracing::error!("Failed to parse Stripe event: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(WebhookResponse { success: false, message: format!("Parse error: {}", e) }),
            );
        }
    };

    // Only handle checkout.session.completed
    if event.event_type != "checkout.session.completed" {
        tracing::info!("Ignoring event type: {}", event.event_type);
        return (
            StatusCode::OK,
            Json(WebhookResponse { success: true, message: "Event ignored".into() }),
        );
    }

    let session = &event.data.object;
    let email = match session.email() {
        Some(e) => e.to_lowercase(),
        None => {
            tracing::error!("No customer email in checkout session");
            return (
                StatusCode::BAD_REQUEST,
                Json(WebhookResponse { success: false, message: "No customer email".into() }),
            );
        }
    };

    // Determine tier from metadata or amount
    let tier = session.tier_from_metadata()
        .unwrap_or_else(|| session.tier_from_amount());

    // Generate license key
    let expiry_epoch = (chrono::Utc::now() + chrono::Duration::days(config.license_duration_days as i64)).timestamp() as u64;
    let license_key = generate_license_key(&email, tier, expiry_epoch);
    let expiry_str = chrono::DateTime::from_timestamp(expiry_epoch as i64, 0)
        .map(|dt| dt.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    tracing::info!(
        "Generated {} license for {}: {} (expires {})",
        tier, email, license_key, expiry_str
    );

    // Send email
    match send_license_email(&config, &email, &license_key, tier, &expiry_str).await {
        Ok(()) => {
            tracing::info!("License email sent to {}", email);
            (
                StatusCode::OK,
                Json(WebhookResponse {
                    success: true,
                    message: format!("License key emailed to {}", email),
                }),
            )
        }
        Err(e) => {
            tracing::error!("Failed to send license email to {}: {}", email, e);
            // Still return 200 so Stripe doesn't retry — log the key for manual recovery
            tracing::error!("MANUAL RECOVERY — License key for {}: {}", email, license_key);
            (
                StatusCode::OK,
                Json(WebhookResponse {
                    success: false,
                    message: format!("License generated but email failed: {}. Key logged for manual delivery.", e),
                }),
            )
        }
    }
}

// Manual key generation endpoint (admin use)
#[derive(Deserialize)]
struct GenerateRequest {
    email: String,
    tier: String,
    admin_key: String,
}

#[derive(Serialize)]
struct GenerateResponse {
    success: bool,
    license_key: Option<String>,
    expiry: Option<String>,
    message: String,
}

async fn generate_key(
    State(state): State<Arc<ServerState>>,
    Json(req): Json<GenerateRequest>,
) -> (StatusCode, Json<GenerateResponse>) {
    let config = &state.config;
    // Simple admin auth — in production, use proper auth
    let expected_admin_key = env_or("ADMIN_KEY", "nexus-admin-change-me");
    if req.admin_key != expected_admin_key {
        return (
            StatusCode::UNAUTHORIZED,
            Json(GenerateResponse { success: false, license_key: None, expiry: None, message: "Unauthorized".into() }),
        );
    }

    let tier = req.tier.to_uppercase();
    if !["PRO", "ENT"].contains(&tier.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(GenerateResponse { success: false, license_key: None, expiry: None, message: "Tier must be PRO or ENT".into() }),
        );
    }

    let expiry_epoch = (chrono::Utc::now() + chrono::Duration::days(config.license_duration_days as i64)).timestamp() as u64;
    let license_key = generate_license_key(&req.email, &tier, expiry_epoch);
    let expiry_str = chrono::DateTime::from_timestamp(expiry_epoch as i64, 0)
        .map(|dt| dt.format("%Y-%m-%d").to_string())
        .unwrap_or_default();

    tracing::info!("Admin generated {} license for {}: {}", tier, req.email, license_key);

    (
        StatusCode::OK,
        Json(GenerateResponse {
            success: true,
            license_key: Some(license_key),
            expiry: Some(expiry_str),
            message: format!("License key generated for {}", req.email),
        }),
    )
}

// ── OAuth Flow ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct OAuthStartQuery {
    callback_port: u16,
}

#[derive(Deserialize)]
struct OAuthCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

// Google OAuth info response
#[derive(Deserialize)]
struct GoogleUserInfo {
    email: Option<String>,
    name: Option<String>,
}

// GitHub types
#[derive(Deserialize)]
struct GitHubTokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct GitHubUserInfo {
    name: Option<String>,
    email: Option<String>,
}

#[derive(Deserialize)]
struct GitHubEmail {
    email: String,
    primary: bool,
}

fn urlencoding(s: &str) -> String {
    s.bytes().map(|b| match b {
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => format!("{}", b as char),
        _ => format!("%{:02X}", b),
    }).collect()
}

async fn auth_google_start(
    State(state): State<Arc<ServerState>>,
    Query(q): Query<OAuthStartQuery>,
) -> Result<Redirect, (StatusCode, String)> {
    let config = &state.config;
    if config.google_client_id.is_empty() {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "Google OAuth not configured".into()));
    }
    let redirect_uri = format!("{}/auth/google/callback", config.server_url);
    // Encode callback_port in state so we get it back
    let state = format!("port_{}", q.callback_port);
    let url = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=email%20profile&state={}&access_type=offline",
        urlencoding(&config.google_client_id),
        urlencoding(&redirect_uri),
        urlencoding(&state),
    );
    Ok(Redirect::temporary(&url))
}

async fn auth_google_callback(
    State(state): State<Arc<ServerState>>,
    Query(q): Query<OAuthCallbackQuery>,
) -> Result<Redirect, (StatusCode, String)> {
    let config = &state.config;
    if let Some(err) = q.error {
        return Err((StatusCode::BAD_REQUEST, format!("OAuth error: {}", err)));
    }
    let code = q.code.ok_or((StatusCode::BAD_REQUEST, "Missing code".into()))?;
    let state = q.state.unwrap_or_default();
    let callback_port: u16 = state.strip_prefix("port_")
        .and_then(|p| p.parse().ok())
        .ok_or((StatusCode::BAD_REQUEST, "Invalid state".into()))?;

    let redirect_uri = format!("{}/auth/google/callback", config.server_url);
    let client = reqwest::Client::new();

    // Exchange code for token
    let token_res = client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("code", code.as_str()),
            ("client_id", config.google_client_id.as_str()),
            ("client_secret", config.google_client_secret.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("grant_type", "authorization_code"),
        ])
        .send().await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Token exchange failed: {}", e)))?;

    #[derive(Deserialize)]
    struct TokenRes { access_token: String }
    let token: TokenRes = token_res.json().await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Token parse failed: {}", e)))?;

    // Get user info
    let user_info: GoogleUserInfo = client
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
        .bearer_auth(&token.access_token)
        .send().await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("User info failed: {}", e)))?
        .json().await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("User info parse failed: {}", e)))?;

    let email = user_info.email.unwrap_or_default();
    let name = user_info.name.unwrap_or_default();

    tracing::info!("Google OAuth success: {} ({})", name, email);

    // Redirect back to desktop app
    let redirect = format!(
        "http://127.0.0.1:{}?provider=google&email={}&name={}",
        callback_port, urlencoding(&email), urlencoding(&name)
    );
    Ok(Redirect::temporary(&redirect))
}

async fn auth_github_start(
    State(state): State<Arc<ServerState>>,
    Query(q): Query<OAuthStartQuery>,
) -> Result<Redirect, (StatusCode, String)> {
    let config = &state.config;
    if config.github_client_id.is_empty() {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "GitHub OAuth not configured".into()));
    }
    let redirect_uri = format!("{}/auth/github/callback", config.server_url);
    let state = format!("port_{}", q.callback_port);
    let url = format!(
        "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope=user:email&state={}",
        urlencoding(&config.github_client_id),
        urlencoding(&redirect_uri),
        urlencoding(&state),
    );
    Ok(Redirect::temporary(&url))
}

async fn auth_github_callback(
    State(state): State<Arc<ServerState>>,
    Query(q): Query<OAuthCallbackQuery>,
) -> Result<Redirect, (StatusCode, String)> {
    let config = &state.config;
    if let Some(err) = q.error {
        return Err((StatusCode::BAD_REQUEST, format!("OAuth error: {}", err)));
    }
    let code = q.code.ok_or((StatusCode::BAD_REQUEST, "Missing code".into()))?;
    let state = q.state.unwrap_or_default();
    let callback_port: u16 = state.strip_prefix("port_")
        .and_then(|p| p.parse().ok())
        .ok_or((StatusCode::BAD_REQUEST, "Invalid state".into()))?;

    let redirect_uri = format!("{}/auth/github/callback", config.server_url);
    let client = reqwest::Client::new();

    // Exchange code for token
    let token: GitHubTokenResponse = client
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .form(&[
            ("client_id", config.github_client_id.as_str()),
            ("client_secret", config.github_client_secret.as_str()),
            ("code", code.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
        ])
        .send().await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Token exchange failed: {}", e)))?
        .json().await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Token parse failed: {}", e)))?;

    // Get user info
    let user_info: GitHubUserInfo = client
        .get("https://api.github.com/user")
        .header("User-Agent", "BeaverWarrior")
        .bearer_auth(&token.access_token)
        .send().await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("User info failed: {}", e)))?
        .json().await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("User info parse failed: {}", e)))?;

    // Get email (might not be in profile)
    let email = if let Some(ref e) = user_info.email {
        e.clone()
    } else {
        let emails: Vec<GitHubEmail> = client
            .get("https://api.github.com/user/emails")
            .header("User-Agent", "BeaverWarrior")
            .bearer_auth(&token.access_token)
            .send().await
            .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Emails failed: {}", e)))?
            .json().await
            .unwrap_or_default();
        emails.into_iter().find(|e| e.primary).map(|e| e.email).unwrap_or_default()
    };

    let name = user_info.name.unwrap_or_default();
    tracing::info!("GitHub OAuth success: {} ({})", name, email);

    let redirect = format!(
        "http://127.0.0.1:{}?provider=github&email={}&name={}",
        callback_port, urlencoding(&email), urlencoding(&name)
    );
    Ok(Redirect::temporary(&redirect))
}

// ── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env()
            .add_directive("license_server=info".parse().unwrap()))
        .init();

    let config = AppConfig::from_env();
    let port = config.port;
    let state = Arc::new(ServerState {
        config,
        users: UserStore::new(),
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/auth/signup", post(auth_signup))
        .route("/auth/login", post(auth_login))
        .route("/webhook/stripe", post(stripe_webhook))
        .route("/admin/generate", post(generate_key))
        .route("/auth/google", get(auth_google_start))
        .route("/auth/google/callback", get(auth_google_callback))
        .route("/auth/github", get(auth_github_start))
        .route("/auth/github/callback", get(auth_github_callback))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    tracing::info!("License server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
