import { requireAuth, requirePro } from "@/lib/auth";
import { requireHostedService } from "@/lib/commissioning";
import { readBoundedJsonObject, requestBodyErrorResponse } from "@/lib/http-body";
import { createServiceClient } from "@/lib/supabase-server";

const MAX_TEAM_VAULT_PUSH_BODY_BYTES = 2_000_000;

type LegacyKeyShare = {
  ephemeral_pk: string;
  nonce: string;
  ciphertext: string;
};

type StoredWrappedKey = string | LegacyKeyShare;

type PushBody = {
  encrypted_blob?: string;
  expected_version?: number;
  wrappedKeys?: Record<string, StoredWrappedKey>;
  key_shares?: Record<string, StoredWrappedKey>;
};

function isLegacyKeyShare(value: unknown): value is LegacyKeyShare {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const candidate = value as Partial<LegacyKeyShare>;
  return (
    typeof candidate.ephemeral_pk === "string" &&
    typeof candidate.nonce === "string" &&
    typeof candidate.ciphertext === "string"
  );
}

function isStoredWrappedKey(value: unknown): value is StoredWrappedKey {
  return typeof value === "string" || isLegacyKeyShare(value);
}

/**
 * GET /api/v1/teams/:team_id/vaults/:project_id — Pull team vault.
 *
 * Returns the encrypted blob, version, and the caller's per-recipient
 * wrapped key (if present). The plaintext is decrypted client-side; the
 * server never sees the symmetric key.
 *
 * Response shape:
 *   { encrypted_blob, version, wrappedKey?, my_share?, missing_key?: true }
 *   - missing_key=true means the caller has not yet uploaded a public
 *     key to this team — see POST /api/v1/teams/:team_id/key first.
 */
export async function GET(
  req: Request,
  { params }: { params: Promise<{ team_id: string; project_id: string }> }
) {
  const commissioningGate = requireHostedService("teams");
  if (commissioningGate) return commissioningGate;

  const authResult = await requireAuth(req);
  if (authResult instanceof Response) return authResult;
  const { team_id, project_id } = await params;

  const supabase = createServiceClient();

  const { data: membership } = await supabase
    .from("team_members")
    .select("public_key")
    .eq("team_id", team_id)
    .eq("user_id", authResult.userId)
    .maybeSingle();

  if (!membership) {
    return Response.json(
      {
        error: "not_a_member",
        message:
          "You are not a member of this team. Ask the owner to invite you with `phantom team invite <TEAM_ID> <github-login>`.",
      },
      { status: 403 }
    );
  }
  if (!membership.public_key) {
    return Response.json(
      { error: "missing_key", message: "Register your public key first via POST /key" },
      { status: 412 }
    );
  }

  const { data: vault } = await supabase
    .from("team_vault_blobs")
    .select("encrypted_blob, version, key_shares")
    .eq("team_id", team_id)
    .eq("project_id", project_id)
    .maybeSingle();

  if (!vault) {
    return Response.json({ error: "vault not found" }, { status: 404 });
  }

  const wrappedKeys = (vault.key_shares ?? {}) as Record<string, StoredWrappedKey>;
  const wrappedKey = wrappedKeys[authResult.userId];
  if (!wrappedKey) {
    // Vault exists but no share for this member — they were added after
    // last push. The next pusher must include them.
    return Response.json(
      {
        error: "no_share",
        message:
          "This team vault has no key share for you yet. Ask a member who can read it to run `phantom team vault push` again.",
      },
      { status: 412 }
    );
  }

  return Response.json({
    encrypted_blob: vault.encrypted_blob,
    version: vault.version,
    wrappedKey,
    // Backward compatibility for current CLI/MCP releases.
    my_share: wrappedKey,
  });
}

/**
 * POST /api/v1/teams/:team_id/vaults/:project_id — Push team vault.
 *
 * Body: {
 *   encrypted_blob,
 *   expected_version,            // for optimistic concurrency
 *   wrappedKeys: { user_id: ciphertext, ... }
 * }
 *
 * Server validates that wrappedKeys covers every team member that has
 * a public_key registered. Members without a registered key are
 * implicitly excluded (they'll get 412 missing_key on pull until they
 * register and the next push includes them).
 *
 * Pro plan required (matches the user-vault push semantics).
 */
export async function POST(
  req: Request,
  { params }: { params: Promise<{ team_id: string; project_id: string }> }
) {
  const commissioningGate = requireHostedService("teams");
  if (commissioningGate) return commissioningGate;

  const authResult = await requireAuth(req);
  if (authResult instanceof Response) return authResult;
  const { team_id, project_id } = await params;
  const proGate = requirePro(authResult);
  if (proGate) return proGate;

  let body: PushBody;
  try {
    body = await readBoundedJsonObject(req, MAX_TEAM_VAULT_PUSH_BODY_BYTES);
  } catch (error) {
    return requestBodyErrorResponse(error);
  }
  const { encrypted_blob, expected_version } = body;
  const wrappedKeys = body.wrappedKeys ?? body.key_shares;

  if (
    typeof encrypted_blob !== "string" ||
    !encrypted_blob ||
    !wrappedKeys ||
    typeof wrappedKeys !== "object" ||
    Array.isArray(wrappedKeys)
  ) {
    return Response.json(
      { error: "encrypted_blob and wrappedKeys required" },
      { status: 400 }
    );
  }
  if (encrypted_blob.length > 1_000_000) {
    return Response.json(
      { error: "encrypted_blob too large (max 1MB)" },
      { status: 413 }
    );
  }
  if (
    typeof expected_version !== "number" ||
    !Number.isInteger(expected_version) ||
    expected_version < 0
  ) {
    return Response.json(
      { error: "expected_version must be a non-negative integer" },
      { status: 400 }
    );
  }
  if (!Object.values(wrappedKeys).every(isStoredWrappedKey)) {
    return Response.json(
      { error: "wrappedKeys values must be ciphertext strings" },
      { status: 400 }
    );
  }
  const expectedVersion = expected_version;

  const supabase = createServiceClient();

  // Caller must be a member.
  const { data: membership } = await supabase
    .from("team_members")
    .select("public_key")
    .eq("team_id", team_id)
    .eq("user_id", authResult.userId)
    .maybeSingle();
  if (!membership) {
    return Response.json(
      {
        error: "not_a_member",
        message:
          "You are not a member of this team. Ask the owner to invite you with `phantom team invite <TEAM_ID> <github-login>`.",
      },
      { status: 403 }
    );
  }

  // Validate that wrappedKeys covers every member with a registered public_key.
  const { data: members } = await supabase
    .from("team_members")
    .select("user_id, public_key")
    .eq("team_id", team_id)
    .not("public_key", "is", null);

  const required = (members ?? [])
    .filter((m) => m.public_key)
    .map((m) => m.user_id);
  const provided = Object.keys(wrappedKeys);
  const missing = required.filter((u) => !provided.includes(u));
  const extra = provided.filter((u) => !required.includes(u));

  if (missing.length || extra.length) {
    return Response.json(
      {
        error: "shares_mismatch",
        missing,
        extra,
        message:
          "wrappedKeys must cover exactly the team members that have registered public keys.",
      },
      { status: 400 }
    );
  }

  // Optimistic concurrency
  const { data: existing } = await supabase
    .from("team_vault_blobs")
    .select("version")
    .eq("team_id", team_id)
    .eq("project_id", project_id)
    .maybeSingle();

  if (existing && (expectedVersion === 0 || existing.version !== expectedVersion)) {
    return Response.json(
      {
        error: "version_conflict",
        server_version: existing.version,
        message: "Server has a newer version. Pull, merge, and push again.",
      },
      { status: 409 }
    );
  }

  if (existing) {
    const next_version = existing.version + 1;
    const { data: updated, error } = await supabase
      .from("team_vault_blobs")
      .update({
        encrypted_blob,
        version: next_version,
        key_shares: wrappedKeys,
      })
      .eq("team_id", team_id)
      .eq("project_id", project_id)
      .eq("version", expectedVersion)
      .select("version")
      .maybeSingle();

    if (error || !updated) {
      return Response.json(
        {
          error: "version_conflict",
          server_version: existing.version,
          message: "Server has a newer version. Pull, merge, and push again.",
        },
        { status: 409 }
      );
    }

    return Response.json({ version: updated.version, members_covered: required.length });
  }

  if (expectedVersion !== 0) {
    return Response.json(
      {
        error: "version_conflict",
        server_version: 0,
        message: "No team vault exists yet. Push again with expected_version=0.",
      },
      { status: 409 }
    );
  }

  const { data: inserted, error } = await supabase
    .from("team_vault_blobs")
    .insert({
      team_id,
      project_id,
      encrypted_blob,
      version: 1,
      key_shares: wrappedKeys,
    })
    .select("version")
    .single();

  if (error) {
    if (error.code === "23505") {
      const { data: raced } = await supabase
        .from("team_vault_blobs")
        .select("version")
        .eq("team_id", team_id)
        .eq("project_id", project_id)
        .maybeSingle();

      return Response.json(
        {
          error: "version_conflict",
          server_version: raced?.version ?? 1,
          message: "Server has a newer version. Pull, merge, and push again.",
        },
        { status: 409 }
      );
    }

    return Response.json(
      {
        error: "server_error",
        message:
          "Failed to save the team vault. Try again, or email mason@ashlr.ai if this persists.",
      },
      { status: 500 }
    );
  }

  return Response.json({ version: inserted.version, members_covered: required.length });
}
