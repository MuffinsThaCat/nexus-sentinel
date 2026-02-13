import { NextRequest, NextResponse } from "next/server";
import { findCustomerByEmail, getCustomerTier } from "@/lib/auth-utils";

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
      return NextResponse.json({
        success: true,
        tier: "FREE",
      });
    }

    const tier = await getCustomerTier(customer.id);

    return NextResponse.json({
      success: true,
      tier,
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Unknown error";
    console.error("Tier check error:", message);
    return NextResponse.json(
      { success: false, message: "Server error checking tier" },
      { status: 500 }
    );
  }
}
