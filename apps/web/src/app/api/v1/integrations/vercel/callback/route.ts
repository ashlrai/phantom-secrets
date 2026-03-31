import { createServiceClient } from "@/lib/supabase-server";

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const code = searchParams.get("code");
  const configurationId = searchParams.get("configurationId");
  const teamId = searchParams.get("teamId");

  if (!code) {
    return Response.json({ error: "Missing code" }, { status: 400 });
  }

  // Exchange code for access token
  const tokenRes = await fetch("https://api.vercel.com/v2/oauth/access_token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: process.env.VERCEL_INTEGRATION_CLIENT_ID!,
      client_secret: process.env.VERCEL_INTEGRATION_CLIENT_SECRET!,
      code,
      redirect_uri: "https://phm.dev/api/v1/integrations/vercel/callback",
    }),
  });

  const tokenData = await tokenRes.json();

  if (!tokenData.access_token) {
    return Response.json({ error: "OAuth failed" }, { status: 400 });
  }

  // Store the token (for now, just save it — we'll link to user accounts later)
  const supabase = createServiceClient();
  await supabase.from("platform_tokens").upsert({
    user_id: tokenData.user_id || "pending", // Will be linked when user connects Phantom account
    platform: "vercel",
    access_token: tokenData.access_token,
    team_id: teamId || null,
  }, { onConflict: "user_id,platform" });

  // Redirect to success page
  return Response.redirect("https://phm.dev/integrations/vercel/success");
}
