import { NextRequest, NextResponse } from "next/server";
import { getStripe, hashPassword, findCustomerByEmail } from "@/lib/auth-utils";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  try {
    const { email, password, name, company } = await req.json();

    if (!email || !password || !name) {
      return NextResponse.json(
        { success: false, message: "Email, password, and name are required" },
        { status: 400 }
      );
    }

    if (!process.env.STRIPE_SECRET_KEY) {
      return NextResponse.json(
        { success: false, message: "Server misconfigured: missing Stripe key" },
        { status: 500 }
      );
    }

    const emailClean = email.trim().toLowerCase();

    // Check if customer already exists
    const existing = await findCustomerByEmail(emailClean);
    if (existing && existing.metadata?.password_hash) {
      return NextResponse.json(
        { success: false, message: "An account with this email already exists" },
        { status: 409 }
      );
    }

    // Hash password
    const { hash, salt } = await hashPassword(password);

    // Create Stripe Customer
    const customer = await getStripe().customers.create({
      email: emailClean,
      name: name.trim(),
      metadata: {
        password_hash: hash,
        password_salt: salt,
        company: company?.trim() || "",
        created_via: "desktop_app",
      },
    });

    return NextResponse.json({
      success: true,
      message: "Account created successfully",
      email: customer.email,
      name: customer.name,
      tier: "FREE",
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Unknown error";
    console.error("Signup error:", message);
    return NextResponse.json(
      { success: false, message: "Server error during signup" },
      { status: 500 }
    );
  }
}
