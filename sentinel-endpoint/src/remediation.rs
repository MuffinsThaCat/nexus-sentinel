use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};

/// LLM-powered remediation engine for generating actionable security advice.
///
/// Pro-tier feature: accepts alert context (severity, component, title, details)
/// and returns step-by-step remediation instructions via a configurable
/// OpenAI-compatible API endpoint.  Results are cached by (component, title)
/// to avoid redundant calls.

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationRequest {
    pub severity: String,
    pub component: String,
    pub title: String,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationResponse {
    pub advice: String,
    pub cached: bool,
    pub model: String,
    pub generated_at: i64,
}

// ── Server request/response ───────────────────────────────────────────

#[derive(Serialize)]
struct ServerRemediationRequest {
    email: String,
    severity: String,
    component: String,
    title: String,
    details: String,
}

#[derive(Deserialize)]
struct ServerRemediationResponse {
    advice: String,
    model: String,
}

// ── Engine ───────────────────────────────────────────────────────────────────

const PRODUCTION_ENDPOINT: &str = "https://beaverwarrior.com/api/v1/remediation";

pub struct RemediationEngine {
    cache: RwLock<HashMap<String, RemediationResponse>>,
    endpoint: String,
    total_requests: AtomicU64,
    cache_hits: AtomicU64,
}

impl RemediationEngine {
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            endpoint: PRODUCTION_ENDPOINT.to_string(),
            total_requests: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
        }
    }

    /// Cache key for deduplication.
    fn cache_key(req: &RemediationRequest) -> String {
        format!("{}::{}", req.component, req.title)
    }

    /// Build the system prompt for security remediation.
    fn system_prompt() -> String {
        "You are a world-class cybersecurity remediation advisor embedded in Beaver Warrior, \
         a desktop endpoint security suite. Given a security alert, provide clear, actionable, \
         step-by-step remediation instructions that a sysadmin or power-user can follow immediately.\n\n\
         Rules:\n\
         - Be concise: max 4-6 numbered steps\n\
         - Include exact commands (macOS/Linux/Windows) when applicable\n\
         - Mention which tool or setting to use\n\
         - If the threat is critical, lead with the containment step\n\
         - End with a verification step to confirm the fix\n\
         - Never say \"consult your IT team\" — you ARE the IT team\n\
         - Format as plain text with numbered steps, no markdown headers".to_string()
    }

    /// Build the user prompt from the alert context.
    fn user_prompt(req: &RemediationRequest) -> String {
        format!(
            "Security Alert:\n\
             Severity: {}\n\
             Component: {}\n\
             Title: {}\n\
             Details: {}\n\n\
             Provide step-by-step remediation instructions.",
            req.severity, req.component, req.title, req.details
        )
    }

    /// Generate remediation advice for a Pro user.
    ///
    /// `email` is the user's email — the Beaver Warrior server looks up the
    /// Stripe customer, validates Pro subscription, and proxies to Claude.
    /// Returns cached result if available, falls back to heuristic advice
    /// if the server is unreachable.
    pub async fn generate(&self, req: &RemediationRequest, email: &str) -> RemediationResponse {
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        // Check cache first
        let key = Self::cache_key(req);
        if let Some(cached) = self.cache.read().get(&key) {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
            return RemediationResponse {
                advice: cached.advice.clone(),
                cached: true,
                model: cached.model.clone(),
                generated_at: cached.generated_at,
            };
        }

        // Call the Beaver Warrior production server
        if let Some(resp) = self.call_server(req, email).await {
            let entry = RemediationResponse {
                advice: resp.advice.clone(),
                cached: false,
                model: resp.model.clone(),
                generated_at: chrono::Utc::now().timestamp(),
            };
            self.cache.write().insert(key, entry.clone());
            return entry;
        }

        // Fallback: built-in heuristic advice if server unreachable
        let advice = self.heuristic_advice(req);
        let entry = RemediationResponse {
            advice,
            cached: false,
            model: "builtin-heuristic".into(),
            generated_at: chrono::Utc::now().timestamp(),
        };
        self.cache.write().insert(key, entry.clone());
        entry
    }

    /// Call the Beaver Warrior production server.
    /// Server validates Pro license via Stripe email lookup, then proxies to Claude.
    async fn call_server(&self, req: &RemediationRequest, email: &str) -> Option<RemediationResponse> {
        let body = ServerRemediationRequest {
            email: email.to_string(),
            severity: req.severity.clone(),
            component: req.component.clone(),
            title: req.title.clone(),
            details: req.details.clone(),
        };

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .ok()?;

        let resp = client
            .post(&self.endpoint)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .ok()?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            tracing::warn!("Remediation server returned {} — {}", status, body_text);
            return None;
        }

        let server_resp: ServerRemediationResponse = resp.json().await.ok()?;

        Some(RemediationResponse {
            advice: server_resp.advice.trim().to_string(),
            cached: false,
            model: server_resp.model,
            generated_at: chrono::Utc::now().timestamp(),
        })
    }

    /// Built-in heuristic remediation when the LLM API is unavailable.
    fn heuristic_advice(&self, req: &RemediationRequest) -> String {
        let component = req.component.to_lowercase();
        let title_lower = req.title.to_lowercase();

        // Malware / download guard
        if component.contains("malware") || component.contains("download") {
            return "1. Quarantine the flagged file immediately — do NOT open it.\n\
                    2. Run a full system scan: open Beaver Warrior → Malware Scanner → Full Scan.\n\
                    3. Check recent downloads folder for other suspicious files.\n\
                    4. If the file was executed, isolate the machine from the network.\n\
                    5. Review running processes for unfamiliar entries (Activity Monitor / Task Manager).\n\
                    6. Verify: re-scan the quarantine folder to confirm the threat is contained.".into();
        }

        // Ransomware
        if component.contains("ransomware") || title_lower.contains("ransomware") {
            return "1. IMMEDIATELY disconnect the machine from the network (Wi-Fi off, Ethernet unplugged).\n\
                    2. Do NOT pay the ransom — it does not guarantee recovery.\n\
                    3. Identify the ransomware variant from the ransom note or encrypted file extension.\n\
                    4. Check nomoreransom.org for free decryptors matching your variant.\n\
                    5. Restore affected files from your most recent clean backup.\n\
                    6. Verify: confirm restored files open correctly, then run a full scan before reconnecting.".into();
        }

        // USB / removable media
        if component.contains("usb") {
            return "1. Safely eject the flagged USB device immediately.\n\
                    2. Scan the device on an isolated machine before re-inserting.\n\
                    3. Review Beaver Warrior → USB Guard → Device Allowlist.\n\
                    4. Add trusted devices to the allowlist by serial number.\n\
                    5. Enable USB autorun blocking in system preferences.\n\
                    6. Verify: re-insert the device and confirm no alerts fire.".into();
        }

        // Process anomaly
        if component.contains("process") {
            return "1. Identify the suspicious process: note its PID and executable path.\n\
                    2. Check if the process is known: `codesign -dvv <path>` (macOS) or check digital signature (Windows).\n\
                    3. If unsigned or unknown, terminate it: `kill <PID>` or Task Manager → End Task.\n\
                    4. Search the executable hash on VirusTotal.\n\
                    5. If malicious, delete the binary and check for persistence (launch agents, startup items).\n\
                    6. Verify: monitor process list for 5 minutes to ensure it doesn't respawn.".into();
        }

        // File integrity
        if component.contains("file_integrity") || component.contains("file integrity") {
            return "1. Review the changed file — compare against your known-good baseline.\n\
                    2. Check `git log` or Time Machine for the last legitimate version.\n\
                    3. If the change is unauthorized, restore from backup.\n\
                    4. Investigate who/what modified the file: check recent process activity and login events.\n\
                    5. Update your baseline if the change is intentional.\n\
                    6. Verify: re-run integrity check to confirm the hash matches the updated baseline.".into();
        }

        // Privilege escalation
        if component.contains("privilege") || title_lower.contains("privilege") || title_lower.contains("escalat") {
            return "1. Identify the user/process that triggered the escalation alert.\n\
                    2. If unexpected, revoke elevated privileges immediately.\n\
                    3. Check sudo/admin logs: `last` and `/var/log/auth.log` (Linux) or Event Viewer (Windows).\n\
                    4. Review user accounts for unauthorized additions to admin/sudoers groups.\n\
                    5. Rotate passwords for any compromised accounts.\n\
                    6. Verify: confirm only authorized accounts retain elevated access.".into();
        }

        // Login anomaly
        if component.contains("login") || title_lower.contains("brute") || title_lower.contains("login") {
            return "1. Identify the source IP/user of the anomalous login attempt.\n\
                    2. If it's a brute-force attack, block the source IP in your firewall.\n\
                    3. Force a password reset for the targeted account.\n\
                    4. Enable MFA if not already active.\n\
                    5. Review recent successful logins for signs of compromise.\n\
                    6. Verify: monitor login logs for 24 hours to confirm the attack has stopped.".into();
        }

        // Network / firewall
        if component.contains("firewall") || component.contains("ids") || component.contains("network") {
            return "1. Identify the source and destination of the flagged traffic.\n\
                    2. If the source is internal, investigate the originating machine for compromise.\n\
                    3. Block the suspicious IP/port in your firewall rules.\n\
                    4. Check for data exfiltration: review outbound transfer volumes.\n\
                    5. Update IDS signatures if this is a new attack pattern.\n\
                    6. Verify: confirm the blocked traffic no longer appears in the alert feed.".into();
        }

        // Scheduled task
        if component.contains("scheduled") || component.contains("cron") || title_lower.contains("scheduled") {
            return "1. Review the newly created/modified scheduled task details.\n\
                    2. Check the command it executes — is it a known legitimate tool?\n\
                    3. If suspicious, disable the task: `launchctl unload` (macOS) or `schtasks /Delete` (Windows).\n\
                    4. Investigate who created it: check creation timestamp against login events.\n\
                    5. Scan the target executable with your malware scanner.\n\
                    6. Verify: list all scheduled tasks and confirm no unauthorized entries remain.".into();
        }

        // Clipboard
        if component.contains("clipboard") {
            return "1. Clear your clipboard immediately: copy a blank string.\n\
                    2. Identify which application accessed the clipboard at the flagged time.\n\
                    3. If the app is untrusted, terminate it and revoke its permissions.\n\
                    4. Check for clipboard manager extensions that may be logging data.\n\
                    5. Review System Preferences → Privacy → Paste permissions.\n\
                    6. Verify: monitor clipboard access for the next hour to confirm no further leaks.".into();
        }

        // Generic fallback
        format!(
            "1. Review the alert details carefully: {} — {}.\n\
             2. Isolate the affected system or component if the severity is Critical or High.\n\
             3. Collect evidence: screenshots, logs, timestamps.\n\
             4. Cross-reference the alert with recent system changes or user activity.\n\
             5. Apply the most restrictive mitigation available (block, quarantine, disable).\n\
             6. Verify: re-check the alert feed to confirm the issue is resolved.",
            req.title, req.details
        )
    }

    /// Stats for monitoring.
    pub fn stats(&self) -> serde_json::Value {
        serde_json::json!({
            "total_requests": self.total_requests.load(Ordering::Relaxed),
            "cache_hits": self.cache_hits.load(Ordering::Relaxed),
            "cache_size": self.cache.read().len(),
            "endpoint": self.endpoint,
        })
    }

    /// Clear the cache.
    pub fn clear_cache(&self) {
        self.cache.write().clear();
    }
}
