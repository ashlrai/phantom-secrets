import { requireAuth } from "@/lib/auth";
import { isHostedServiceCommissioned } from "@/lib/commissioning";
import { createServiceClient } from "@/lib/supabase-server";

export async function GET(req: Request) {
  const authResult = await requireAuth(req);
  if (authResult instanceof Response) return authResult;

  const supabase = createServiceClient();

  const { data: user, error: userError } = await supabase
    .from("users")
    .select("github_login, email")
    .eq("id", authResult.userId)
    .maybeSingle();

  if (userError) {
    return Response.json({ error: "Failed to load user" }, { status: 500 });
  }

  if (!user) {
    return Response.json({ error: "user not found" }, { status: 404 });
  }

  // `/me` remains available for CLI identity/status. Hosted vault metadata is
  // omitted until that separate service is explicitly commissioned.
  let vaultsCount: number | undefined;
  if (isHostedServiceCommissioned("personal_vaults")) {
    const { count, error: countError } = await supabase
      .from("vault_blobs")
      .select("*", { count: "exact", head: true })
      .eq("user_id", authResult.userId);
    if (countError || !Number.isSafeInteger(count) || count === null || count < 0) {
      return Response.json({ error: "Failed to load vault count" }, { status: 500 });
    }
    vaultsCount = count;
  }

  return Response.json({
    github_login: user.github_login,
    email: user.email,
    plan: authResult.plan,
    ...(vaultsCount === undefined ? {} : { vaults_count: vaultsCount }),
  });
}
