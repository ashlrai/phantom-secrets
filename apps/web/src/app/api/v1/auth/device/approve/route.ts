import { createServiceClient } from "@/lib/supabase-server";
import { createClient } from "@supabase/supabase-js";

export async function POST(req: Request) {
  const body = await req.json();
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
  const githubLogin =
    user.user_metadata?.user_name ||
    user.user_metadata?.preferred_username ||
    user.email?.split("@")[0] ||
    "unknown";

  await supabase.from("users").upsert(
    {
      id: user.id,
      github_login: githubLogin,
      email: user.email,
    },
    { onConflict: "id" }
  );

  // Find and approve the device token
  const cleanCode = user_code.replace(/-/g, "").toUpperCase();
  const { data: token, error: tokenError } = await supabase
    .from("device_tokens")
    .select("id, status, expires_at")
    .eq("user_code", cleanCode)
    .eq("status", "pending")
    .single();

  if (tokenError || !token) {
    return Response.json(
      { error: "Invalid or expired code. Please try again." },
      { status: 400 }
    );
  }

  if (new Date(token.expires_at) < new Date()) {
    return Response.json({ error: "Code expired" }, { status: 400 });
  }

  // Approve
  await supabase
    .from("device_tokens")
    .update({ status: "approved", user_id: user.id })
    .eq("id", token.id);

  return Response.json({ status: "approved" });
}
