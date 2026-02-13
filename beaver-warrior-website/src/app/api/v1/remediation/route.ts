import { NextRequest, NextResponse } from "next/server";
import { findCustomerByEmail, getCustomerTier } from "@/lib/auth-utils";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Claude system prompt for security remediation advice
const SYSTEM_PROMPT = `You are a senior cybersecurity analyst embedded in the Beaver Warrior endpoint security platform.
Given a security alert, provide clear, actionable remediation steps.

Rules:
- Be concise (under 300 words)
- Number your steps
- Include both immediate actions and longer-term hardening
- If the alert might be a false positive, say so and explain how to verify
- Reference relevant frameworks (MITRE ATT&CK, NIST) when appropriate`;

interface RemediationBody {
  email: string;
  severity: string;
  component: string;
  title: string;
  details: string;
}

// ── Heuristic fallback when Claude is unavailable ──────────────────────
function fallbackAdvice(body: RemediationBody): string {
  const comp = (body.component || "").toLowerCase();
  const title = (body.title || "").toLowerCase();

  if (comp.includes("malware") || comp.includes("download")) {
    return "1. Quarantine the flagged file immediately — do NOT open it.\n2. Run a full system scan: open Beaver Warrior → Malware Scanner → Full Scan.\n3. Check recent downloads folder for other suspicious files.\n4. If the file was executed, isolate the machine from the network.\n5. Review running processes for unfamiliar entries (Activity Monitor / Task Manager).\n6. Verify: re-scan the quarantine folder to confirm the threat is contained.";
  }
  if (comp.includes("ransomware") || title.includes("ransomware")) {
    return "1. IMMEDIATELY disconnect the machine from the network (Wi-Fi off, Ethernet unplugged).\n2. Do NOT pay the ransom — it does not guarantee recovery.\n3. Identify the ransomware variant from the ransom note or encrypted file extension.\n4. Check nomoreransom.org for free decryptors matching your variant.\n5. Restore affected files from your most recent clean backup.\n6. Verify: confirm restored files open correctly, then run a full scan before reconnecting.";
  }
  if (comp.includes("usb")) {
    return "1. Safely eject the flagged USB device immediately.\n2. Scan the device on an isolated machine before re-inserting.\n3. Review Beaver Warrior → USB Guard → Device Allowlist.\n4. Add trusted devices to the allowlist by serial number.\n5. Enable USB autorun blocking in system preferences.\n6. Verify: re-insert the device and confirm no alerts fire.";
  }
  if (comp.includes("process")) {
    return "1. Identify the suspicious process: note its PID and executable path.\n2. Check if the process is known: `codesign -dvv <path>` (macOS) or check digital signature (Windows).\n3. If unsigned or unknown, terminate it: `kill <PID>` or Task Manager → End Task.\n4. Search the executable hash on VirusTotal.\n5. If malicious, delete the binary and check for persistence (launch agents, startup items).\n6. Verify: monitor process list for 5 minutes to ensure it doesn't respawn.";
  }
  if (comp.includes("file_integrity") || comp.includes("file integrity")) {
    return "1. Review the changed file — compare against your known-good baseline.\n2. Check git log or Time Machine for the last legitimate version.\n3. If the change is unauthorized, restore from backup.\n4. Investigate who/what modified the file: check recent process activity and login events.\n5. Update your baseline if the change is intentional.\n6. Verify: re-run integrity check to confirm the hash matches the updated baseline.";
  }
  if (comp.includes("privilege") || title.includes("privilege") || title.includes("escalat")) {
    return "1. Identify the user/process that triggered the escalation alert.\n2. If unexpected, revoke elevated privileges immediately.\n3. Check sudo/admin logs: `last` and `/var/log/auth.log` (Linux) or Event Viewer (Windows).\n4. Review user accounts for unauthorized additions to admin/sudoers groups.\n5. Rotate passwords for any compromised accounts.\n6. Verify: confirm only authorized accounts retain elevated access.";
  }
  if (comp.includes("login") || title.includes("brute") || title.includes("login")) {
    return "1. Identify the source IP/user of the anomalous login attempt.\n2. If it's a brute-force attack, block the source IP in your firewall.\n3. Force a password reset for the targeted account.\n4. Enable MFA if not already active.\n5. Review recent successful logins for signs of compromise.\n6. Verify: monitor login logs for 24 hours to confirm the attack has stopped.";
  }
  if (comp.includes("firewall") || comp.includes("ids") || comp.includes("network")) {
    return "1. Identify the source and destination of the flagged traffic.\n2. If the source is internal, investigate the originating machine for compromise.\n3. Block the suspicious IP/port in your firewall rules.\n4. Check for data exfiltration: review outbound transfer volumes.\n5. Update IDS signatures if this is a new attack pattern.\n6. Verify: confirm the blocked traffic no longer appears in the alert feed.";
  }

  // Generic fallback
  return `1. Review the alert details carefully: ${body.title} — ${body.details}.\n2. Isolate the affected system or component if the severity is Critical or High.\n3. Collect evidence: screenshots, logs, timestamps.\n4. Cross-reference the alert with recent system changes or user activity.\n5. Apply the most restrictive mitigation available (block, quarantine, disable).\n6. Verify: re-check the alert feed to confirm the issue is resolved.`;
}

export async function POST(req: NextRequest) {
  try {
    const body: RemediationBody = await req.json();

    // ── Validate request ──────────────────────────────────────────
    if (!body.email || !body.title) {
      return NextResponse.json(
        { error: "Missing required fields: email, title" },
        { status: 400 }
      );
    }

    // ── Verify user is Pro via Stripe ─────────────────────────────
    const customer = await findCustomerByEmail(body.email.trim().toLowerCase());
    if (!customer) {
      return NextResponse.json(
        { error: "Account not found" },
        { status: 401 }
      );
    }

    const tier = await getCustomerTier(customer.id);
    if (tier !== "PRO" && tier !== "ENT") {
      return NextResponse.json(
        { error: "Remediation advice requires a Pro or Enterprise subscription" },
        { status: 403 }
      );
    }

    // ── Call Claude (with graceful fallback) ──────────────────────
    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) {
      console.error("ANTHROPIC_API_KEY not configured — using fallback");
      return NextResponse.json({
        advice: fallbackAdvice(body),
        model: "builtin-heuristic",
      });
    }

    const userPrompt = [
      `Severity: ${body.severity}`,
      `Component: ${body.component}`,
      `Alert: ${body.title}`,
      `Details: ${body.details}`,
      "",
      "Provide step-by-step remediation advice for this security alert.",
    ].join("\n");

    let claudeRes: Response;
    try {
      claudeRes = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": apiKey,
          "anthropic-version": "2023-06-01",
        },
        body: JSON.stringify({
          model: "claude-sonnet-4-20250514",
          max_tokens: 1024,
          system: SYSTEM_PROMPT,
          messages: [{ role: "user", content: userPrompt }],
        }),
      });
    } catch (fetchErr) {
      // Network error, DNS failure, timeout, etc.
      console.error("Claude API fetch failed:", fetchErr);
      return NextResponse.json({
        advice: fallbackAdvice(body),
        model: "builtin-heuristic",
      });
    }

    if (!claudeRes.ok) {
      const errText = await claudeRes.text().catch(() => "");
      console.error(`Claude API error ${claudeRes.status}: ${errText}`);
      // Graceful fallback — billing issue, rate limit, outage, etc.
      return NextResponse.json({
        advice: fallbackAdvice(body),
        model: "builtin-heuristic",
      });
    }

    const claudeData = await claudeRes.json();
    const advice =
      claudeData.content?.[0]?.text?.trim() ?? fallbackAdvice(body);
    const model = claudeData.model ?? "claude-sonnet-4-20250514";

    return NextResponse.json({
      advice,
      model: advice === fallbackAdvice(body) ? "builtin-heuristic" : model,
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Unknown error";
    console.error("Remediation endpoint error:", message);
    return NextResponse.json(
      { error: "Server error generating remediation advice" },
      { status: 500 }
    );
  }
}
