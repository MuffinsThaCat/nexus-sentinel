use serde::{Serialize, Deserialize};
use parking_lot::RwLock;
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use crate::sentinel::Tier;
use crate::config::SentinelConfig;

// ── Security Constants ───────────────────────────────────────────────────────

const HASH_ITERATIONS: u32 = 100_000;
const MAX_LOGIN_ATTEMPTS: u32 = 5;
const LOCKOUT_SECS: i64 = 300; // 5 minutes

// 256-bit HMAC key for license signature verification.
// This key is compiled into the binary. The same key must be used
// server-side when issuing license keys after Stripe payment.
const LICENSE_HMAC_KEY: &[u8] = b"\xb7\x3a\xf1\x08\x4d\xe9\x52\xc6\x91\x7b\xa0\x3e\xd4\x68\x5f\x2c\xe3\x1a\x9d\x74\x06\xbc\x83\x47\xf5\x62\x0e\xab\xd9\x15\x8c\x70";

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub id: String,
    pub email: String,
    pub name: String,
    pub company: Option<String>,
    pub tier: Tier,
    pub created_at: String,
    pub endpoints: usize,
    pub team_size: usize,
    pub license_valid: bool,
    pub license_expiry: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredUser {
    id: String,
    email: String,
    name: String,
    company: Option<String>,
    password_hash: String,
    password_salt: String,
    tier: Tier,
    created_at: String,
    endpoints: usize,
    team_size: usize,
    license_key: Option<String>,
    license_expiry: Option<String>,
    failed_attempts: u32,
    locked_until: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthState {
    pub logged_in: bool,
    pub user: Option<UserProfile>,
    pub session_token: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthResult {
    pub success: bool,
    pub message: String,
    pub state: AuthState,
}

#[derive(Debug, Clone, Serialize)]
pub struct LicenseResult {
    pub success: bool,
    pub message: String,
    pub tier: Tier,
    pub expiry: Option<String>,
    pub state: AuthState,
}

#[derive(Debug, Clone, Serialize)]
pub struct PaymentInfo {
    pub url: String,
    pub tier: String,
    pub price: String,
}

// ── Server Auth Response ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct ServerAuthResponse {
    success: bool,
    message: String,
    email: Option<String>,
    name: Option<String>,
    tier: Option<String>,
}

// ── Password Hashing (PBKDF2-style iterated SHA-256) ─────────────────────────

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
    // Constant-time comparison to prevent timing attacks
    let computed = hash_password(password, salt);
    if computed.len() != stored_hash.len() { return false; }
    let mut diff = 0u8;
    for (a, b) in computed.bytes().zip(stored_hash.bytes()) {
        diff |= a ^ b;
    }
    diff == 0
}

// ── License Key System ───────────────────────────────────────────────────────
//
// Format: NS-{TIER}-{hex(email_hash)}-{expiry_epoch}-{hex(hmac_sig)}
//
// Only our server (or anyone with LICENSE_HMAC_KEY) can generate valid keys.
// The app verifies locally: recompute HMAC over (email + tier + expiry)
// and compare to the signature in the key.

fn license_sign(email: &str, tier: Tier, expiry_epoch: u64) -> String {
    let tier_str = match tier { Tier::Free => "FREE", Tier::Pro => "PRO", Tier::Enterprise => "ENT" };
    let payload = format!("{}:{}:{}", email.to_lowercase(), tier_str, expiry_epoch);
    let mut h = Sha256::new();
    h.update(LICENSE_HMAC_KEY);
    h.update(payload.as_bytes());
    hex::encode(h.finalize())
}

pub fn generate_license_key(email: &str, tier: Tier, expiry_epoch: u64) -> String {
    let tier_code = match tier { Tier::Free => "FREE", Tier::Pro => "PRO", Tier::Enterprise => "ENT" };
    let email_hash = {
        let mut h = Sha256::new();
        h.update(email.to_lowercase().as_bytes());
        hex::encode(h.finalize())[..12].to_string()
    };
    let sig = license_sign(email, tier, expiry_epoch);
    let sig_short = &sig[..16];
    format!("NS-{}-{}-{}-{}", tier_code, email_hash, expiry_epoch, sig_short)
}

fn verify_license_key(key: &str, email: &str) -> Option<(Tier, u64)> {
    let parts: Vec<&str> = key.split('-').collect();
    // NS-TIER-emailhash-expiry-sig  → 5 parts
    if parts.len() != 5 || parts[0] != "NS" { return None; }

    let tier = match parts[1] {
        "FREE" => Tier::Free,
        "PRO" => Tier::Pro,
        "ENT" => Tier::Enterprise,
        _ => return None,
    };

    let expiry: u64 = parts[3].parse().ok()?;
    let provided_sig = parts[4];

    // Verify email hash matches
    let email_hash = {
        let mut h = Sha256::new();
        h.update(email.to_lowercase().as_bytes());
        hex::encode(h.finalize())[..12].to_string()
    };
    if parts[2] != email_hash { return None; }

    // Verify HMAC signature
    let full_sig = license_sign(email, tier, expiry);
    let expected_sig = &full_sig[..16];

    // Constant-time compare
    if provided_sig.len() != expected_sig.len() { return None; }
    let mut diff = 0u8;
    for (a, b) in provided_sig.bytes().zip(expected_sig.bytes()) {
        diff |= a ^ b;
    }
    if diff != 0 { return None; }

    // Check expiry
    let now = chrono::Utc::now().timestamp() as u64;
    if expiry < now { return None; } // Expired

    Some((tier, expiry))
}

// ── UserStore ────────────────────────────────────────────────────────────────

pub struct UserStore {
    users: RwLock<HashMap<String, StoredUser>>,
    session: RwLock<Option<(String, String)>>,
    data_path: PathBuf,
    config: SentinelConfig,
}

impl UserStore {
    pub fn new() -> Self {
        let data_path = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("nexus-sentinel");
        std::fs::create_dir_all(&data_path).ok();
        let file = data_path.join("users.json");

        let users: HashMap<String, StoredUser> = if file.exists() {
            match std::fs::read_to_string(&file) {
                Ok(json) => serde_json::from_str(&json).unwrap_or_default(),
                Err(_) => HashMap::new(),
            }
        } else {
            HashMap::new()
        };

        let session_file = data_path.join("session.json");
        let session = if session_file.exists() {
            match std::fs::read_to_string(&session_file) {
                Ok(json) => serde_json::from_str(&json).unwrap_or(None),
                Err(_) => None,
            }
        } else {
            None
        };

        let config = SentinelConfig::load();

        UserStore {
            users: RwLock::new(users),
            session: RwLock::new(session),
            data_path,
            config,
        }
    }

    fn save_users(&self) {
        let users = self.users.read();
        if let Ok(json) = serde_json::to_string_pretty(&*users) {
            let _ = std::fs::write(self.data_path.join("users.json"), json);
        }
    }

    fn save_session(&self) {
        let session = self.session.read();
        if let Ok(json) = serde_json::to_string(&*session) {
            let _ = std::fs::write(self.data_path.join("session.json"), json);
        }
    }

    fn is_license_valid(u: &StoredUser) -> bool {
        if u.tier == Tier::Free { return true; } // Free needs no license
        match (&u.license_key, &u.license_expiry) {
            (Some(key), Some(_expiry)) => {
                verify_license_key(key, &u.email).is_some()
            }
            _ => false,
        }
    }

    fn effective_tier(u: &StoredUser) -> Tier {
        if u.tier == Tier::Free { return Tier::Free; }
        if Self::is_license_valid(u) { u.tier } else { Tier::Free }
    }

    fn user_to_profile(u: &StoredUser) -> UserProfile {
        let valid = Self::is_license_valid(u);
        UserProfile {
            id: u.id.clone(),
            email: u.email.clone(),
            name: u.name.clone(),
            company: u.company.clone(),
            tier: Self::effective_tier(u),
            created_at: u.created_at.clone(),
            endpoints: u.endpoints,
            team_size: u.team_size,
            license_valid: valid || u.tier == Tier::Free,
            license_expiry: u.license_expiry.clone(),
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

    pub fn get_auth_state(&self) -> AuthState {
        let session = self.session.read();
        if let Some((token, email)) = session.as_ref() {
            let users = self.users.read();
            if let Some(user) = users.get(email) {
                return AuthState {
                    logged_in: true,
                    user: Some(Self::user_to_profile(user)),
                    session_token: Some(token.clone()),
                };
            }
        }
        AuthState { logged_in: false, user: None, session_token: None }
    }

    pub async fn signup(&self, email: &str, password: &str, name: &str, company: Option<&str>) -> AuthResult {
        let email_clean = email.trim().to_lowercase();

        // Call server
        let client = reqwest::Client::new();
        let mut body = serde_json::json!({
            "email": email_clean,
            "password": password,
            "name": name.trim(),
        });
        if let Some(c) = company {
            if !c.trim().is_empty() {
                body["company"] = serde_json::Value::String(c.trim().to_string());
            }
        }

        let res = match client
            .post(format!("{}/auth/signup", self.config.server_url.trim_end_matches('/')))
            .json(&body)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => return AuthResult {
                success: false,
                message: format!("Cannot reach server: {}", e),
                state: self.get_auth_state(),
            },
        };

        let server_resp: ServerAuthResponse = match res.json().await {
            Ok(r) => r,
            Err(e) => return AuthResult {
                success: false,
                message: format!("Invalid server response: {}", e),
                state: self.get_auth_state(),
            },
        };

        if !server_resp.success {
            return AuthResult { success: false, message: server_resp.message, state: self.get_auth_state() };
        }

        // Server approved — cache user locally and create session
        let resp_email = server_resp.email.unwrap_or(email_clean);
        let resp_name = server_resp.name.unwrap_or_else(|| name.trim().to_string());
        self.cache_user(&resp_email, &resp_name, company, Tier::Free);

        let token = uuid::Uuid::new_v4().to_string();
        *self.session.write() = Some((token, resp_email));
        self.save_session();

        let state = self.get_auth_state();
        AuthResult { success: true, message: "Account created successfully".into(), state }
    }

    pub async fn login(&self, email: &str, password: &str) -> AuthResult {
        let email_clean = email.trim().to_lowercase();

        let client = reqwest::Client::new();
        let body = serde_json::json!({
            "email": email_clean,
            "password": password,
        });

        let res = match client
            .post(format!("{}/auth/login", self.config.server_url.trim_end_matches('/')))
            .json(&body)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => return AuthResult {
                success: false,
                message: format!("Cannot reach server: {}", e),
                state: self.get_auth_state(),
            },
        };

        let server_resp: ServerAuthResponse = match res.json().await {
            Ok(r) => r,
            Err(e) => return AuthResult {
                success: false,
                message: format!("Invalid server response: {}", e),
                state: self.get_auth_state(),
            },
        };

        if !server_resp.success {
            return AuthResult { success: false, message: server_resp.message, state: self.get_auth_state() };
        }

        let resp_email = server_resp.email.unwrap_or(email_clean);
        let resp_name = server_resp.name.unwrap_or_default();
        let tier_str = server_resp.tier.unwrap_or_else(|| "FREE".into());
        let tier = match tier_str.as_str() {
            "PRO" => Tier::Pro,
            "ENT" => Tier::Enterprise,
            _ => Tier::Free,
        };
        self.cache_user(&resp_email, &resp_name, None, tier);

        let token = uuid::Uuid::new_v4().to_string();
        *self.session.write() = Some((token, resp_email));
        self.save_session();

        let state = self.get_auth_state();
        AuthResult { success: true, message: "Logged in successfully".into(), state }
    }

    fn cache_user(&self, email: &str, name: &str, company: Option<&str>, tier: Tier) {
        let mut users = self.users.write();
        if !users.contains_key(email) {
            let user = StoredUser {
                id: uuid::Uuid::new_v4().to_string(),
                email: email.to_string(),
                name: name.to_string(),
                company: company.map(|c| c.trim().to_string()).filter(|c| !c.is_empty()),
                password_hash: String::new(),
                password_salt: String::new(),
                tier,
                created_at: chrono::Utc::now().to_rfc3339(),
                endpoints: 0,
                team_size: 1,
                license_key: None,
                license_expiry: None,
                failed_attempts: 0,
                locked_until: None,
            };
            users.insert(email.to_string(), user);
        } else if let Some(u) = users.get_mut(email) {
            if !name.is_empty() { u.name = name.to_string(); }
            u.tier = tier;
        }
        drop(users);
        self.save_users();
    }

    pub fn logout(&self) -> AuthState {
        *self.session.write() = None;
        self.save_session();
        AuthState { logged_in: false, user: None, session_token: None }
    }

    pub fn activate_license(&self, license_key: &str) -> LicenseResult {
        let session = self.session.read();
        let email = match session.as_ref() {
            Some((_, e)) => e.clone(),
            None => return LicenseResult {
                success: false, message: "Not logged in".into(),
                tier: Tier::Free, expiry: None, state: self.get_auth_state(),
            },
        };
        drop(session);

        let key = license_key.trim().to_uppercase();
        match verify_license_key(&key, &email) {
            Some((tier, expiry_epoch)) => {
                let mut users = self.users.write();
                if let Some(user) = users.get_mut(&email) {
                    user.tier = tier;
                    user.license_key = Some(key);
                    let expiry_dt = chrono::DateTime::from_timestamp(expiry_epoch as i64, 0)
                        .unwrap_or_else(|| chrono::Utc::now());
                    user.license_expiry = Some(expiry_dt.to_rfc3339());
                    drop(users);
                    self.save_users();
                    let state = self.get_auth_state();
                    return LicenseResult {
                        success: true,
                        message: format!("License activated! Upgraded to {:?}.", tier),
                        tier,
                        expiry: Some(expiry_dt.to_rfc3339()),
                        state,
                    };
                }
                LicenseResult { success: false, message: "User not found".into(), tier: Tier::Free, expiry: None, state: self.get_auth_state() }
            }
            None => LicenseResult {
                success: false,
                message: "Invalid or expired license key. Make sure the key matches your account email.".into(),
                tier: Tier::Free, expiry: None, state: self.get_auth_state(),
            },
        }
    }

    pub fn get_payment_url(&self, tier: Tier) -> Option<PaymentInfo> {
        if !self.config.has_stripe() { return None; }

        let session = self.session.read();
        let email = session.as_ref().map(|(_, e)| e.clone())?;

        let (url_base, price) = match tier {
            Tier::Pro => (self.config.stripe.pro_payment_link.as_str(), "$29/user/mo"),
            Tier::Enterprise => (self.config.stripe.enterprise_payment_link.as_str(), "$99/user/mo"),
            Tier::Free => return None,
        };
        let url = format!("{}?prefilled_email={}", url_base, urlencoding(&email));
        Some(PaymentInfo {
            url,
            tier: format!("{:?}", tier),
            price: price.to_string(),
        })
    }

    pub fn update_profile(&self, name: Option<&str>, company: Option<&str>) -> AuthResult {
        let session = self.session.read();
        if let Some((_, email)) = session.as_ref() {
            let mut users = self.users.write();
            if let Some(user) = users.get_mut(email) {
                if let Some(n) = name {
                    if !n.trim().is_empty() { user.name = n.trim().to_string(); }
                }
                if let Some(c) = company {
                    user.company = if c.trim().is_empty() { None } else { Some(c.trim().to_string()) };
                }
                drop(users);
                drop(session);
                self.save_users();
                let state = self.get_auth_state();
                return AuthResult { success: true, message: "Profile updated".into(), state };
            }
        }
        AuthResult { success: false, message: "Not logged in".into(), state: self.get_auth_state() }
    }

    pub fn oauth_login(&self, email: &str, name: &str, provider: &str) -> AuthResult {
        let email = email.trim().to_lowercase();
        let mut users = self.users.write();

        if !users.contains_key(&email) {
            let user = StoredUser {
                id: uuid::Uuid::new_v4().to_string(),
                email: email.clone(),
                name: name.trim().to_string(),
                company: None,
                password_hash: format!("oauth:{}", provider.to_lowercase()),
                password_salt: String::new(),
                tier: Tier::Free,
                created_at: chrono::Utc::now().to_rfc3339(),
                endpoints: 0,
                team_size: 1,
                license_key: None,
                license_expiry: None,
                failed_attempts: 0,
                locked_until: None,
            };
            users.insert(email.clone(), user);
        }
        drop(users);
        self.save_users();

        let token = uuid::Uuid::new_v4().to_string();
        *self.session.write() = Some((token, email));
        self.save_session();

        let state = self.get_auth_state();
        AuthResult { success: true, message: format!("Signed in with {}", provider), state }
    }

    pub fn get_session_email(&self) -> Option<String> {
        let session = self.session.read();
        session.as_ref().map(|(_, e)| e.clone())
    }

    pub fn server_url(&self) -> String {
        self.config.server_url.trim_end_matches('/').to_string()
    }

    pub fn update_cached_tier(&self, email: &str, tier: Tier) {
        let mut users = self.users.write();
        if let Some(user) = users.get_mut(email) {
            user.tier = tier;
        }
        drop(users);
        self.save_users();
    }
}

fn urlencoding(s: &str) -> String {
    s.replace(':', "%3A").replace('/', "%2F").replace('@', "%40").replace(' ', "%20")
}

unsafe impl Send for UserStore {}
unsafe impl Sync for UserStore {}

// ── Tauri Commands ───────────────────────────────────────────────────────────

#[tauri::command]
pub fn get_auth_state(store: tauri::State<'_, Arc<UserStore>>, backend: tauri::State<'_, Arc<crate::sentinel::SentinelBackend>>) -> AuthState {
    let state = store.get_auth_state();
    if let Some(ref user) = state.user {
        *backend.current_tier.write() = user.tier;
    }
    state
}

#[tauri::command]
pub async fn signup(store: tauri::State<'_, Arc<UserStore>>, backend: tauri::State<'_, Arc<crate::sentinel::SentinelBackend>>, email: String, password: String, name: String, company: Option<String>) -> Result<AuthResult, String> {
    let result = store.signup(&email, &password, &name, company.as_deref()).await;
    if result.success {
        *backend.current_tier.write() = crate::sentinel::Tier::Free;
    }
    Ok(result)
}

#[tauri::command]
pub async fn login(store: tauri::State<'_, Arc<UserStore>>, backend: tauri::State<'_, Arc<crate::sentinel::SentinelBackend>>, email: String, password: String) -> Result<AuthResult, String> {
    let result = store.login(&email, &password).await;
    if result.success {
        if let Some(ref state) = Some(&result.state) {
            if let Some(ref user) = state.user {
                *backend.current_tier.write() = user.tier;
            }
        }
    }
    Ok(result)
}

#[tauri::command]
pub fn logout(store: tauri::State<'_, Arc<UserStore>>) -> AuthState {
    store.logout()
}

#[tauri::command]
pub fn activate_license(store: tauri::State<'_, Arc<UserStore>>, license_key: String) -> LicenseResult {
    store.activate_license(&license_key)
}

#[tauri::command]
pub fn get_payment_url(store: tauri::State<'_, Arc<UserStore>>, tier: Tier) -> Option<PaymentInfo> {
    store.get_payment_url(tier)
}

#[tauri::command]
pub fn update_profile(store: tauri::State<'_, Arc<UserStore>>, name: Option<String>, company: Option<String>) -> AuthResult {
    store.update_profile(name.as_deref(), company.as_deref())
}

#[tauri::command]
pub async fn get_portal_url(store: tauri::State<'_, Arc<UserStore>>) -> Result<String, String> {
    let email = match store.get_session_email() {
        Some(e) => e,
        None => return Ok(String::new()),
    };
    let base = store.server_url();

    let client = reqwest::Client::new();
    let url = format!("{}/auth/portal", base);
    let body = serde_json::json!({ "email": email });

    let res = client.post(&url).json(&body).send().await.map_err(|e| e.to_string())?;

    #[derive(serde::Deserialize)]
    struct PortalResponse { success: bool, url: Option<String> }

    let resp: PortalResponse = res.json().await.map_err(|e| e.to_string())?;
    Ok(resp.url.unwrap_or_default())
}

#[tauri::command]
pub async fn refresh_tier(store: tauri::State<'_, Arc<UserStore>>, backend: tauri::State<'_, Arc<crate::sentinel::SentinelBackend>>) -> Result<String, String> {
    let email = match store.get_session_email() {
        Some(e) => e,
        None => return Ok("Free".to_string()),
    };
    let base = store.server_url();

    let client = reqwest::Client::new();
    let url = format!("{}/auth/tier", base);
    let body = serde_json::json!({ "email": email });

    let res = client.post(&url).json(&body).send().await.map_err(|e| e.to_string())?;

    #[derive(serde::Deserialize)]
    struct TierResponse { success: bool, tier: Option<String> }

    let resp: TierResponse = res.json().await.map_err(|e| e.to_string())?;

    let tier_str = resp.tier.unwrap_or_else(|| "FREE".into());
    let tier = match tier_str.as_str() {
        "PRO" => Tier::Pro,
        "ENT" => Tier::Enterprise,
        _ => Tier::Free,
    };

    store.update_cached_tier(&email, tier);
    *backend.current_tier.write() = tier;
    Ok(format!("{:?}", tier))
}
