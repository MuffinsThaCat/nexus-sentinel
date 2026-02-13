import { NextRequest, NextResponse } from "next/server";
import { findCustomerByEmail, getStripe } from "@/lib/auth-utils";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  try {
    const { email } = await req.json();

    if (!email) {
      return NextResponse.json(
        { success: false, message: "Email is required" },
        { status: 400 }
      );
    }

    const emailClean = email.trim().toLowerCase();
    const customer = await findCustomerByEmail(emailClean);

    if (!customer) {
      return NextResponse.json(
        { success: false, message: "No account found for this email" },
        { status: 404 }
      );
    }

    const session = await getStripe().billingPortal.sessions.create({
      customer: customer.id,
      return_url: "https://beaverwarrior.com",
    });

    return NextResponse.json({
      success: true,
      url: session.url,
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Unknown error";
    console.error("Portal session error:", message);
    return NextResponse.json(
      { success: false, message: "Failed to create portal session" },
      { status: 500 }
    );
  }
}
