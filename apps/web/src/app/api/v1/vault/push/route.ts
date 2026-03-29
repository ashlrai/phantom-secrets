import { requireAuth, requirePro } from "@/lib/auth";
import { createServiceClient } from "@/lib/supabase-server";

export async function PUT(req: Request) {
  const authResult = await requireAuth(req);
  if (authResult instanceof Response) return authResult;

  const body = await req.json();
  const { project_id, encrypted_blob, expected_version } = body;

  if (!project_id || !encrypted_blob) {
    return Response.json(
      { error: "project_id and encrypted_blob required" },
      { status: 400 }
    );
  }

  // Reject oversized blobs (1MB limit — more than enough for any vault)
  if (encrypted_blob.length > 1_000_000) {
    return Response.json(
      { error: "encrypted_blob too large (max 1MB)" },
      { status: 413 }
    );
  }

  const supabase = createServiceClient();

  // Check free tier limit: 1 vault for free users
  if (authResult.plan !== "pro") {
    const { count } = await supabase
      .from("vault_blobs")
      .select("*", { count: "exact", head: true })
      .eq("user_id", authResult.userId);

    // Check if this is a NEW vault (not an update to an existing one)
    const { data: existing } = await supabase
      .from("vault_blobs")
      .select("id")
      .eq("user_id", authResult.userId)
      .eq("project_id", project_id)
      .single();

    if (!existing && (count ?? 0) >= 1) {
      const proRequired = requirePro(authResult);
      if (proRequired) return proRequired;
    }
  }

  // Check if vault exists
  const { data: existingVault } = await supabase
    .from("vault_blobs")
    .select("id, version")
    .eq("user_id", authResult.userId)
    .eq("project_id", project_id)
    .single();

  if (existingVault) {
    // Update — check optimistic concurrency
    const expectedVer = expected_version ?? 0;
    if (expectedVer !== 0 && existingVault.version !== expectedVer) {
      return Response.json(
        {
          error: "conflict",
          server_version: existingVault.version,
        },
        { status: 409 }
      );
    }

    const newVersion = existingVault.version + 1;
    const { error } = await supabase
      .from("vault_blobs")
      .update({
        encrypted_blob,
        version: newVersion,
      })
      .eq("id", existingVault.id)
      .eq("version", existingVault.version); // TOCTOU guard

    if (error) {
      return Response.json(
        { error: "conflict", server_version: existingVault.version },
        { status: 409 }
      );
    }

    return Response.json({ version: newVersion });
  } else {
    // Insert new vault
    const { error } = await supabase.from("vault_blobs").insert({
      user_id: authResult.userId,
      project_id,
      encrypted_blob,
      version: 1,
    });

    if (error) {
      return Response.json({ error: "Failed to create vault" }, { status: 500 });
    }

    return Response.json({ version: 1 }, { status: 201 });
  }
}
