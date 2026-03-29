import { createServiceClient } from "./supabase-server";
import { createHash } from "crypto";

export interface AuthUser {
  userId: string;
  plan: string;
}

/**
 * Validate a device token from the Authorization header.
 * Returns the user info or null if invalid.
 */
export async function authenticateRequest(
  req: Request
): Promise<AuthUser | null> {
  const authHeader = req.headers.get("authorization");
  if (!authHeader?.startsWith("Bearer ")) return null;

  const token = authHeader.slice(7);
  if (!token) return null;

  const tokenHash = createHash("sha256").update(token).digest("hex");
  const supabase = createServiceClient();

  const { data } = await supabase
    .from("device_tokens")
    .select("user_id, status, expires_at")
    .eq("token_hash", tokenHash)
    .single();

  if (!data) return null;
  if (data.status !== "approved") return null;
  if (new Date(data.expires_at) < new Date()) return null;

  // Get user plan
  const { data: user } = await supabase
    .from("users")
    .select("plan, plan_expires_at")
    .eq("id", data.user_id)
    .single();

  if (!user) return null;

  // Check if plan is still active (grace period for failed payments)
  let effectivePlan = user.plan;
  if (
    user.plan === "pro" &&
    user.plan_expires_at &&
    new Date(user.plan_expires_at) < new Date()
  ) {
    effectivePlan = "free";
  }

  return { userId: data.user_id, plan: effectivePlan };
}

/**
 * Helper: require auth, return 401 Response if not authenticated.
 */
export async function requireAuth(
  req: Request
): Promise<AuthUser | Response> {
  const user = await authenticateRequest(req);
  if (!user) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }
  return user;
}

/**
 * Helper: require Pro plan, return 402 if free tier.
 */
export function requirePro(user: AuthUser): Response | null {
  if (user.plan === "pro") return null;
  return Response.json(
    {
      error: "pro_required",
      message: "This feature requires Phantom Pro ($8/month)",
      checkout_url: "https://phm.dev/pricing",
    },
    { status: 402 }
  );
}
