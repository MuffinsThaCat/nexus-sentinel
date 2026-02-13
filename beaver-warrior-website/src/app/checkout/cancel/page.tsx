"use client";

import Link from "next/link";
import { XCircle, ArrowLeft } from "lucide-react";

export default function CheckoutCancel() {
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
            background: "rgba(239,68,68,0.15)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            margin: "0 auto 1.5rem",
          }}
        >
          <XCircle size={32} style={{ color: "#ef4444" }} />
        </div>

        <h1
          style={{
            fontSize: "2rem",
            fontWeight: 700,
            marginBottom: "0.75rem",
          }}
        >
          Checkout Cancelled
        </h1>

        <p
          style={{
            color: "#94a3b8",
            fontSize: "1.05rem",
            marginBottom: "2rem",
            lineHeight: 1.6,
          }}
        >
          No worries — you weren&apos;t charged. You can always start with the free Community Shield or come back when you&apos;re ready.
        </p>

        <Link
          href="/#pricing"
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
          Back to Pricing
        </Link>
      </div>
    </div>
  );
}
