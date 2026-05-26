import { requireAuth, requirePro } from "@/lib/auth";
import { createServiceClient } from "@/lib/supabase-server";

export async function PUT(req: Request) {
  const authResult = await requireAuth(req);
  if (authResult instanceof Response) return authResult;

  let body;
  try {
    body = await req.json();
  } catch {
    return Response.json({ error: "invalid_json" }, { status: 400 });
  }
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
  if (!Number.isInteger(expected_version) || expected_version < 0) {
    return Response.json(
      { error: "expected_version must be a non-negative integer" },
      { status: 400 }
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
    // Update — expected_version is required so clients cannot
    // accidentally overwrite a newer cloud copy.
    if (expected_version === 0 || existingVault.version !== expected_version) {
      return Response.json(
        {
          error: "conflict",
          server_version: existingVault.version,
        },
        { status: 409 }
      );
    }

    const newVersion = existingVault.version + 1;
    const { data: updatedVault, error } = await supabase
      .from("vault_blobs")
      .update({
        encrypted_blob,
        version: newVersion,
      })
      .eq("id", existingVault.id)
      .eq("version", expected_version)
      .select("version")
      .maybeSingle(); // Atomic compare-and-swap guard

    if (error || !updatedVault) {
      return Response.json(
        { error: "conflict", server_version: existingVault.version },
        { status: 409 }
      );
    }

    return Response.json({ version: updatedVault.version });
  } else {
    if (expected_version !== 0) {
      return Response.json(
        {
          error: "conflict",
          server_version: 0,
        },
        { status: 409 }
      );
    }

    // Insert new vault
    const { data: insertedVault, error } = await supabase
      .from("vault_blobs")
      .insert({
        user_id: authResult.userId,
        project_id,
        encrypted_blob,
        version: 1,
      })
      .select("version")
      .single();

    if (error) {
      if (error.code === "23505") {
        const { data: racedVault } = await supabase
          .from("vault_blobs")
          .select("version")
          .eq("user_id", authResult.userId)
          .eq("project_id", project_id)
          .maybeSingle();

        return Response.json(
          { error: "conflict", server_version: racedVault?.version ?? 1 },
          { status: 409 }
        );
      }

      return Response.json({ error: "Failed to create vault" }, { status: 500 });
    }

    return Response.json({ version: insertedVault.version }, { status: 201 });
  }
}
