"use client";

import Link from "next/link";
import { CheckCircle, Download, ArrowLeft } from "lucide-react";

export default function CheckoutSuccess() {
  return (
    <div
      style={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: "2rem",
      }}
    >
      <div
        style={{
          maxWidth: "32rem",
          width: "100%",
          textAlign: "center",
        }}
      >
        <div
          style={{
            width: "4rem",
            height: "4rem",
            borderRadius: "50%",
            background: "rgba(16,185,129,0.15)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            margin: "0 auto 1.5rem",
          }}
        >
          <CheckCircle size={32} style={{ color: "#10b981" }} />
        </div>

        <h1
          style={{
            fontSize: "2rem",
            fontWeight: 700,
            marginBottom: "0.75rem",
          }}
        >
          Welcome to Beaver Warrior!
        </h1>

        <p
          style={{
            color: "#94a3b8",
            fontSize: "1.05rem",
            marginBottom: "2rem",
            lineHeight: 1.6,
          }}
        >
          Your subscription is active. Download the app below and sign in with the email you used at checkout to unlock your plan.
        </p>

        <div
          style={{
            display: "flex",
            flexDirection: "column",
            gap: "0.75rem",
          }}
        >
          <a
            href="/BeaverWarrior-macOS.zip"
            download
            style={{
              display: "inline-flex",
              alignItems: "center",
              justifyContent: "center",
              gap: "0.5rem",
              padding: "0.875rem 1.5rem",
              borderRadius: "0.75rem",
              background: "#22d3ee",
              color: "#0f172a",
              fontWeight: 600,
              fontSize: "0.95rem",
              textDecoration: "none",
              transition: "opacity 0.2s",
            }}
          >
            <Download size={18} />
            Download Beaver Warrior
          </a>

          <Link
            href="/"
            style={{
              display: "inline-flex",
              alignItems: "center",
              justifyContent: "center",
              gap: "0.5rem",
              padding: "0.875rem 1.5rem",
              borderRadius: "0.75rem",
              border: "1px solid rgba(100,116,139,0.4)",
              color: "#94a3b8",
              fontWeight: 500,
              fontSize: "0.95rem",
              textDecoration: "none",
              transition: "border-color 0.2s",
            }}
          >
            <ArrowLeft size={16} />
            Back to Home
          </Link>
        </div>
      </div>
    </div>
  );
}
