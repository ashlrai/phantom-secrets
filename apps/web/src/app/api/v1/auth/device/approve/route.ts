import { createServiceClient } from "@/lib/supabase-server";
import { verifiedGithubLoginForUser } from "@/lib/auth";
import { isValidDeviceUserCode, normalizeDeviceUserCode } from "@/lib/device-code";
import { readBoundedJsonObject, requestBodyErrorResponse } from "@/lib/http-body";
import { createClient } from "@supabase/supabase-js";

const MAX_DEVICE_AUTH_BODY_BYTES = 4_096;

export async function POST(req: Request) {
  let body: { user_code?: string };
  try {
    body = await readBoundedJsonObject(req, MAX_DEVICE_AUTH_BODY_BYTES);
  } catch (error) {
    return requestBodyErrorResponse(error);
  }
  const { user_code } = body;

  if (!user_code) {
    return Response.json({ error: "user_code required" }, { status: 400 });
  }

  // Verify the user's Supabase Auth session from the Authorization header
  const authHeader = req.headers.get("authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }

  const supabaseToken = authHeader.slice(7);

  // Create a client with the user's token to get their identity
  const supabaseUser = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    { global: { headers: { Authorization: `Bearer ${supabaseToken}` } } }
  );

  const {
    data: { user },
    error: userError,
  } = await supabaseUser.auth.getUser();

  if (userError || !user) {
    return Response.json({ error: "invalid session" }, { status: 401 });
  }

  const supabase = createServiceClient();

  // Ensure user exists in public.users
  const githubLogin = verifiedGithubLoginForUser(user);
  if (!githubLogin) {
    return Response.json(
      { error: "A verified GitHub identity is required." },
      { status: 403, headers: { "cache-control": "no-store" } }
    );
  }

  const { error: upsertError } = await supabase.from("users").upsert(
    {
      id: user.id,
      github_login: githubLogin,
      email: user.email,
    },
    { onConflict: "id" }
  );
  if (upsertError) {
    return Response.json(
      { error: "Failed to establish the authenticated user." },
      { status: 500, headers: { "cache-control": "no-store" } }
    );
  }

  // Find and approve the device token
  const cleanCode = normalizeDeviceUserCode(user_code);
  if (!isValidDeviceUserCode(cleanCode)) {
    return Response.json({ error: "Invalid code format" }, { status: 400 });
  }

  const nowIso = new Date().toISOString();
  const { data: token, error: tokenError } = await supabase
    .from("device_tokens")
    .select("id, status, expires_at, device_expires_at")
    .eq("user_code", cleanCode)
    .eq("status", "pending")
    .gte("device_expires_at", nowIso)
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();

  if (tokenError || !token) {
    return Response.json(
      { error: "Invalid or expired code. Please try again." },
      { status: 400 }
    );
  }

  // Approve atomically. A concurrent approval can otherwise reassign user_id.
  const { data: approvedToken, error: approveError } = await supabase
    .from("device_tokens")
    .update({
      status: "approved",
      user_id: user.id,
      approved_at: new Date().toISOString(),
    })
    .eq("id", token.id)
    .eq("status", "pending")
    .select("id")
    .maybeSingle();

  if (approveError || !approvedToken) {
    return Response.json(
      { error: "Code was already approved. Please start a new login." },
      { status: 409 }
    );
  }

  return Response.json({ status: "approved" });
}
