import { requireAuth } from "@/lib/auth";
import { createServiceClient } from "@/lib/supabase-server";

export async function GET(req: Request) {
  const authResult = await requireAuth(req);
  if (authResult instanceof Response) return authResult;

  const supabase = createServiceClient();

  const { data: user } = await supabase
    .from("users")
    .select("github_login, email, plan")
    .eq("id", authResult.userId)
    .single();

  if (!user) {
    return Response.json({ error: "user not found" }, { status: 404 });
  }

  // Count vaults
  const { count } = await supabase
    .from("vault_blobs")
    .select("*", { count: "exact", head: true })
    .eq("user_id", authResult.userId);

  return Response.json({
    github_login: user.github_login,
    email: user.email,
    plan: user.plan,
    vaults_count: count ?? 0,
  });
}
