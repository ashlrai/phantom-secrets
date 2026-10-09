import { requireAuth, requirePro } from "@/lib/auth";
import { requireHostedService } from "@/lib/commissioning";
import { readBoundedJsonObject, requestBodyErrorResponse } from "@/lib/http-body";
import { createServiceClient } from "@/lib/supabase-server";

const MAX_VAULT_PUSH_BODY_BYTES = 1_100_000;

type VaultPushBody = {
  project_id?: string;
  encrypted_blob?: string;
  expected_version?: number;
};

export async function PUT(req: Request) {
  const commissioningGate = requireHostedService("personal_vaults");
  if (commissioningGate) return commissioningGate;

  const authResult = await requireAuth(req);
  if (authResult instanceof Response) return authResult;

  let body: VaultPushBody;
  try {
    body = await readBoundedJsonObject(req, MAX_VAULT_PUSH_BODY_BYTES);
  } catch (error) {
    return requestBodyErrorResponse(error);
  }
  const { project_id, encrypted_blob, expected_version } = body;

  if (
    typeof project_id !== "string" ||
    !project_id ||
    typeof encrypted_blob !== "string" ||
    !encrypted_blob
  ) {
    return Response.json(
      { error: "project_id and encrypted_blob required" },
      { status: 400 }
    );
  }

  // Reject oversized blobs (1MB limit — more than enough for any vault)
  if (Buffer.byteLength(encrypted_blob, "utf8") > 1_000_000) {
    return Response.json(
      { error: "encrypted_blob too large (max 1MB)" },
      { status: 413 }
    );
  }
  if (
    typeof expected_version !== "number" ||
    !Number.isSafeInteger(expected_version) ||
    expected_version < 0
  ) {
    return Response.json(
      { error: "expected_version must be a non-negative integer" },
      { status: 400 }
    );
  }

  const supabase = createServiceClient();
  // The database serializes all pushes for this account before checking its
  // quota and version. Legacy plan labels never admit another cloud backup.
  const { data, error } = await supabase.rpc("push_personal_vault", {
    p_user_id: authResult.userId,
    p_project_id: project_id,
    p_encrypted_blob: encrypted_blob,
    p_expected_version: expected_version,
  });

  if (error || !Array.isArray(data) || data.length !== 1) {
    return Response.json({ error: "Failed to save vault" }, { status: 500 });
  }
  const result = data[0];
  if (!result || typeof result !== "object") {
    return Response.json({ error: "Failed to save vault" }, { status: 500 });
  }
  if (result.outcome === "quota_exceeded") {
    return requirePro(authResult) ?? Response.json(
      { error: "feature_unavailable" }, { status: 503 }
    );
  }
  if (result.outcome === "user_missing") {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }
  if (!Number.isSafeInteger(result.version) || result.version < 0) {
    return Response.json({ error: "Failed to save vault" }, { status: 500 });
  }
  if (result.outcome === "conflict") {
    return Response.json(
      { error: "conflict", server_version: result.version },
      { status: 409 }
    );
  }
  if (
    (result.outcome === "created" && result.version === 1) ||
    (result.outcome === "updated" && result.version > 1)
  ) {
    return Response.json(
      { version: result.version },
      { status: result.outcome === "created" ? 201 : 200 }
    );
  }
  return Response.json({ error: "Failed to save vault" }, { status: 500 });
}
