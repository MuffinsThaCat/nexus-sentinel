import { NextRequest, NextResponse } from "next/server";
import { findCustomerByEmail, verifyPassword, getCustomerTier } from "@/lib/auth-utils";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  try {
    const { email, password } = await req.json();

    if (!email || !password) {
      return NextResponse.json(
        { success: false, message: "Email and password are required" },
        { status: 400 }
      );
    }

    const emailClean = email.trim().toLowerCase();

    // Find customer
    const customer = await findCustomerByEmail(emailClean);
    if (!customer || !customer.metadata?.password_hash) {
      return NextResponse.json(
        { success: false, message: "Invalid email or password" },
        { status: 401 }
      );
    }

    // Verify password
    const valid = await verifyPassword(
      password,
      customer.metadata.password_hash,
      customer.metadata.password_salt
    );
    if (!valid) {
      return NextResponse.json(
        { success: false, message: "Invalid email or password" },
        { status: 401 }
      );
    }

    // Get tier from active subscriptions
    const tier = await getCustomerTier(customer.id);

    return NextResponse.json({
      success: true,
      message: "Logged in successfully",
      email: customer.email,
      name: customer.name,
      tier,
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Unknown error";
    console.error("Login error:", message);
    return NextResponse.json(
      { success: false, message: "Server error during login" },
      { status: 500 }
    );
  }
}
