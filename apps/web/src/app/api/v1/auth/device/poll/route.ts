import { createServiceClient } from "@/lib/supabase-server";
import { createHash, randomBytes } from "crypto";

export async function POST(req: Request) {
  const body = await req.json();
  const { device_code } = body;

  if (!device_code) {
    return Response.json({ error: "device_code required" }, { status: 400 });
  }

  const supabase = createServiceClient();

  const { data: token } = await supabase
    .from("device_tokens")
    .select("id, user_id, status, expires_at, token_hash")
    .eq("device_code", device_code)
    .single();

  if (!token) {
    return Response.json({ error: "invalid device_code" }, { status: 400 });
  }

  // Check expiry
  if (new Date(token.expires_at) < new Date()) {
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

    // Store the hash atomically — WHERE token_hash IS NULL prevents TOCTOU race
    const { error: updateError } = await supabase
      .from("device_tokens")
      .update({ token_hash: tokenHash })
      .eq("id", token.id)
      .is("token_hash", null);

    if (updateError) {
      return Response.json({ status: "already_claimed" });
    }

    // Get user info
    const { data: user } = await supabase
      .from("users")
      .select("github_login, email, plan")
      .eq("id", token.user_id)
      .single();

    return Response.json({
      status: "approved",
      access_token: accessToken,
      user: user
        ? {
            github_login: user.github_login,
            email: user.email,
            plan: user.plan,
          }
        : null,
    });
  }

  return Response.json({ status: token.status });
}
