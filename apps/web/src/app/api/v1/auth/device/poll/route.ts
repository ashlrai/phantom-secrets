import { createServiceClient } from "@/lib/supabase-server";
import { readBoundedJsonObject, requestBodyErrorResponse } from "@/lib/http-body";
import { effectivePlan } from "@/lib/plan";
import { createHash, randomBytes } from "crypto";

const CLI_TOKEN_TTL_DAYS = 90;
const MAX_DEVICE_AUTH_BODY_BYTES = 4_096;

export async function POST(req: Request) {
  let body: { device_code?: string };
  try {
    body = await readBoundedJsonObject(req, MAX_DEVICE_AUTH_BODY_BYTES);
  } catch (error) {
    return requestBodyErrorResponse(error);
  }
  const { device_code } = body;

  if (!device_code) {
    return Response.json({ error: "device_code required" }, { status: 400 });
  }

  const supabase = createServiceClient();

  const { data: token } = await supabase
    .from("device_tokens")
    .select("id, user_id, status, expires_at, device_expires_at, token_hash")
    .eq("device_code", device_code)
    .single();

  if (!token) {
    return Response.json({ error: "invalid device_code" }, { status: 400 });
  }

  // Check expiry
  const deviceExpiresAt = token.device_expires_at ?? token.expires_at;
  if (new Date(deviceExpiresAt) < new Date()) {
    await supabase
      .from("device_tokens")
      .update({ status: "expired" })
      .eq("id", token.id);
    return Response.json({ status: "expired" });
  }

  if (token.status === "pending") {
    return Response.json({ status: "pending" });
  }

  if (token.status === "expired") {
    return Response.json({ status: "expired" });
  }

  if (token.status === "approved") {
    // If token already issued, don't reissue
    if (token.token_hash) {
      return Response.json({ status: "already_claimed" });
    }

    // Generate access token
    const accessToken = randomBytes(64).toString("hex");
    const tokenHash = createHash("sha256").update(accessToken).digest("hex");
    const tokenExpiresAt = new Date(
      Date.now() + CLI_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000
    ).toISOString();

    // Store the hash atomically — WHERE token_hash IS NULL prevents TOCTOU race
    const { data: claimedToken, error: updateError } = await supabase
      .from("device_tokens")
      .update({
        token_hash: tokenHash,
        token_expires_at: tokenExpiresAt,
        claimed_at: new Date().toISOString(),
      })
      .eq("id", token.id)
      .is("token_hash", null)
      .select("id")
      .maybeSingle();

    if (updateError || !claimedToken) {
      return Response.json({ status: "already_claimed" });
    }

    // Get user info
    const { data: user } = await supabase
      .from("users")
      .select("github_login, email, plan, plan_expires_at")
      .eq("id", token.user_id)
      .single();

    return Response.json({
      status: "approved",
      access_token: accessToken,
      user: user
        ? {
            github_login: user.github_login,
            email: user.email,
            plan: effectivePlan(user),
          }
        : null,
    });
  }

  return Response.json({ status: token.status });
}
