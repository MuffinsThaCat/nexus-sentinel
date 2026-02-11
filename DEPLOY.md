# Nexus Sentinel — Deployment Guide

Two things to deploy:
1. **Desktop App** — the Tauri app users download and install
2. **License Server** — a small backend that handles Stripe payments and emails license keys

---

## Prerequisites

- [Rust](https://rustup.rs/) (1.77+)
- [Node.js](https://nodejs.org/) (18+)
- [Stripe Account](https://dashboard.stripe.com/register)
- SMTP credentials (Gmail App Password, SendGrid, or AWS SES)

---

## Part 1: Stripe Setup

### 1A. Create Payment Links

1. Go to [Stripe Dashboard → Payment Links](https://dashboard.stripe.com/payment-links)
2. Create **Pro** link:
   - Product: "Nexus Sentinel Pro"
   - Price: $29/month (recurring)
   - Under "After payment" → Collect email address
   - Under "Advanced" → Add metadata: `tier` = `PRO`
   - Copy the link URL (e.g. `https://buy.stripe.com/abc123`)
3. Create **Enterprise** link:
   - Product: "Nexus Sentinel Enterprise"
   - Price: $99/month (recurring)
   - Same settings, metadata: `tier` = `ENT`
   - Copy the link URL

### 1B. Create Webhook

1. Go to [Stripe Dashboard → Webhooks](https://dashboard.stripe.com/webhooks)
2. Click "Add endpoint"
3. URL: `https://your-server.com/webhook/stripe`
4. Events: Select only `checkout.session.completed`
5. Click "Add endpoint"
6. Copy the **Signing secret** (starts with `whsec_`)

---

## Part 2: License Server Deployment

### Option A: Docker (recommended)

```bash
cd sentinel-license-server

# Copy and fill in your credentials
cp .env.example .env
# Edit .env with your real values

# Build
docker build -t nexus-license-server -f Dockerfile ..

# Run
docker run -d \
  --name license-server \
  --env-file .env \
  -p 3001:3001 \
  --restart unless-stopped \
  nexus-license-server
```

### Option B: Direct binary

```bash
# Build release binary
cargo build --release -p sentinel-license-server

# Copy to server
scp target/release/license-server your-server:/opt/nexus/

# On the server, set env vars and run:
export STRIPE_WEBHOOK_SECRET=whsec_xxx
export SMTP_HOST=smtp.gmail.com
export SMTP_PORT=587
export SMTP_USERNAME=you@gmail.com
export SMTP_PASSWORD=your-app-password
export FROM_EMAIL=license@nexus-sentinel.com
export ADMIN_KEY=your-secret-key
export PORT=3001

/opt/nexus/license-server
```

### Option C: Railway / Fly.io / Render

Any platform that runs Docker containers works. Point the Dockerfile at it and set the env vars in their dashboard.

### Verify it's running

```bash
curl https://your-server.com/health
# → "Nexus Sentinel License Server — OK"
```

### Test key generation (admin endpoint)

```bash
curl -X POST https://your-server.com/admin/generate \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","tier":"PRO","admin_key":"your-secret-key"}'
```

This returns a license key you can paste into the desktop app to verify the full flow works.

---

## Part 3: Desktop App — Configure

Edit the config file that gets auto-created on first launch:

**macOS:** `~/Library/Application Support/nexus-sentinel/config.json`
**Linux:** `~/.local/share/nexus-sentinel/config.json`
**Windows:** `%APPDATA%/nexus-sentinel/config.json`

```json
{
  "stripe": {
    "pro_payment_link": "https://buy.stripe.com/your_pro_link",
    "enterprise_payment_link": "https://buy.stripe.com/your_ent_link"
  },
  "oauth": {
    "google_client_id": "xxx.apps.googleusercontent.com",
    "google_client_secret": "GOCSPX-xxx",
    "github_client_id": "Ov23li...",
    "github_client_secret": "..."
  }
}
```

Leave OAuth fields empty if you don't need Google/GitHub sign-in yet — the app will gracefully show "not configured" messages.

---

## Part 4: Desktop App — Build for Distribution

### macOS (.dmg)

```bash
cd sentinel-desktop/frontend
npm install
npm run tauri build
```

Output: `src-tauri/target/release/bundle/dmg/Nexus Sentinel_0.1.0_aarch64.dmg`

### Windows (.msi / .exe)

```bash
npm run tauri build
```

Output: `src-tauri/target/release/bundle/msi/Nexus Sentinel_0.1.0_x64_en-US.msi`

### Linux (.deb / .AppImage)

```bash
npm run tauri build
```

Output: `src-tauri/target/release/bundle/deb/` and `appimage/`

---

## Part 5: OAuth Setup (Optional)

### Google OAuth

1. Go to [Google Cloud Console → APIs & Services → Credentials](https://console.cloud.google.com/apis/credentials)
2. Create project (or select existing)
3. Click "Create Credentials" → "OAuth client ID"
4. Application type: **Desktop app**
5. Name: "Nexus Sentinel"
6. Copy Client ID and Client Secret → paste into `config.json`

### GitHub OAuth

1. Go to [GitHub → Settings → Developer Settings → OAuth Apps](https://github.com/settings/developers)
2. Click "New OAuth App"
3. Application name: "Nexus Sentinel"
4. Homepage URL: `https://nexus-sentinel.com` (or any URL)
5. Authorization callback URL: `http://127.0.0.1` (desktop app handles the port)
6. Copy Client ID and Client Secret → paste into `config.json`

---

## Complete Flow Summary

```
┌─────────────┐     ┌──────────┐     ┌────────────────┐     ┌──────────────┐
│  User opens  │────▶│  Sign up │────▶│  Free tier     │────▶│  Clicks      │
│  desktop app │     │  / login │     │  (works fully) │     │  "Buy Pro"   │
└─────────────┘     └──────────┘     └────────────────┘     └──────┬───────┘
                                                                    │
                                                                    ▼
┌─────────────┐     ┌──────────┐     ┌────────────────┐     ┌──────────────┐
│  Pro tier    │◀────│  Pastes  │◀────│  Receives      │◀────│  Stripe      │
│  activated!  │     │  key in  │     │  license key   │     │  checkout    │
│              │     │  app     │     │  via email      │     │  completes   │
└─────────────┘     └──────────┘     └────────────────┘     └──────────────┘
                                           ▲
                                           │
                                     License Server
                                     (webhook + email)
```

---

## Troubleshooting

**Desktop app shows "not configured" for OAuth:**
→ Edit `config.json` and add your OAuth credentials, then restart the app.

**License key says "Invalid":**
→ Make sure the HMAC key in the license server matches the desktop app. Both should use the same compiled key.

**Email not sending:**
→ Check SMTP credentials. For Gmail, you need an [App Password](https://myaccount.google.com/apppasswords), not your regular password.

**Stripe webhook failing:**
→ Check the webhook signing secret matches `STRIPE_WEBHOOK_SECRET`. Use `stripe listen --forward-to localhost:3001/webhook/stripe` for local testing.
