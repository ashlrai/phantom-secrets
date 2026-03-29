import { requireAuth } from "@/lib/auth";
import { createServiceClient } from "@/lib/supabase-server";

export async function GET(req: Request) {
  const authResult = await requireAuth(req);
  if (authResult instanceof Response) return authResult;

  const { searchParams } = new URL(req.url);
  const projectId = searchParams.get("project_id");

  if (!projectId) {
    return Response.json({ error: "project_id required" }, { status: 400 });
  }

  const supabase = createServiceClient();

  const { data } = await supabase
    .from("vault_blobs")
    .select("encrypted_blob, version")
    .eq("user_id", authResult.userId)
    .eq("project_id", projectId)
    .single();

  if (!data) {
    return Response.json({ error: "vault not found" }, { status: 404 });
  }

  return Response.json({
    encrypted_blob: data.encrypted_blob,
    version: data.version,
  });
}
