import Stripe from "stripe";

export function getStripe() {
  return new Stripe(process.env.STRIPE_SECRET_KEY || "", {
    httpClient: Stripe.createFetchHttpClient(),
  });
}

// PBKDF2 password hashing using Web Crypto API (works in serverless/edge)
export async function hashPassword(password: string, salt?: string): Promise<{ hash: string; salt: string }> {
  const encoder = new TextEncoder();
  const saltBytes = salt
    ? Uint8Array.from(Buffer.from(salt, "hex"))
    : crypto.getRandomValues(new Uint8Array(16));

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltBytes, iterations: 100000, hash: "SHA-256" },
    key,
    256
  );

  return {
    hash: Buffer.from(bits).toString("hex"),
    salt: salt || Buffer.from(saltBytes).toString("hex"),
  };
}

export async function verifyPassword(password: string, storedHash: string, storedSalt: string): Promise<boolean> {
  const { hash } = await hashPassword(password, storedSalt);
  return hash === storedHash;
}

// Look up a Stripe Customer by email
export async function findCustomerByEmail(email: string): Promise<Stripe.Customer | null> {
  const customers = await getStripe().customers.list({ email, limit: 1 });
  if (customers.data.length === 0) return null;
  return customers.data[0];
}

// Determine tier from active Stripe subscriptions
export async function getCustomerTier(customerId: string): Promise<string> {
  const subs = await getStripe().subscriptions.list({
    customer: customerId,
    status: "active",
    limit: 10,
  });

  const proPriceId = process.env.STRIPE_PRO_PRICE_ID;
  const entPriceId = process.env.STRIPE_ENTERPRISE_PRICE_ID;

  for (const sub of subs.data) {
    for (const item of sub.items.data) {
      if (item.price.id === entPriceId) return "ENT";
      if (item.price.id === proPriceId) return "PRO";
    }
  }
  return "FREE";
}
