import { requireAuth, requirePro } from "@/lib/auth";
import { createServiceClient } from "@/lib/supabase-server";

type KeyShare = {
  ephemeral_pk: string;
  nonce: string;
  ciphertext: string;
};

type PushBody = {
  encrypted_blob?: string;
  expected_version?: number;
  key_shares?: Record<string, KeyShare>;
};

/**
 * GET /api/v1/teams/:team_id/vaults/:project_id — Pull team vault.
 *
 * Returns the encrypted blob, version, and the caller's per-recipient
 * key share (if present). The plaintext is decrypted client-side; the
 * server never sees the symmetric key.
 *
 * Response shape:
 *   { encrypted_blob, version, my_share?, missing_key?: true }
 *   - missing_key=true means the caller has not yet uploaded a public
 *     key to this team — see POST /api/v1/teams/:team_id/key first.
 */
export async function GET(
  req: Request,
  { params }: { params: Promise<{ team_id: string; project_id: string }> }
) {
  const { team_id, project_id } = await params;
  const authResult = await requireAuth(req);
  if (authResult instanceof Response) return authResult;

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

  const shares = (vault.key_shares ?? {}) as Record<string, KeyShare>;
  const my_share = shares[authResult.userId];
  if (!my_share) {
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
    my_share,
  });
}

/**
 * POST /api/v1/teams/:team_id/vaults/:project_id — Push team vault.
 *
 * Body: {
 *   encrypted_blob,
 *   expected_version,            // for optimistic concurrency
 *   key_shares: { user_id: KeyShare, ... }
 * }
 *
 * Server validates that key_shares covers every team member that has
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
  const { team_id, project_id } = await params;
  const authResult = await requireAuth(req);
  if (authResult instanceof Response) return authResult;
  const proGate = requirePro(authResult);
  if (proGate) return proGate;

  const body = (await req.json()) as PushBody;
  const { encrypted_blob, expected_version, key_shares } = body;

  if (!encrypted_blob || !key_shares) {
    return Response.json(
      { error: "encrypted_blob and key_shares required" },
      { status: 400 }
    );
  }
  if (encrypted_blob.length > 1_000_000) {
    return Response.json(
      { error: "encrypted_blob too large (max 1MB)" },
      { status: 413 }
    );
  }

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

  // Validate that key_shares covers every member with a registered public_key.
  const { data: members } = await supabase
    .from("team_members")
    .select("user_id, public_key")
    .eq("team_id", team_id)
    .not("public_key", "is", null);

  const required = (members ?? [])
    .filter((m) => m.public_key)
    .map((m) => m.user_id);
  const provided = Object.keys(key_shares);
  const missing = required.filter((u) => !provided.includes(u));
  const extra = provided.filter((u) => !required.includes(u));

  if (missing.length || extra.length) {
    return Response.json(
      {
        error: "shares_mismatch",
        missing,
        extra,
        message:
          "key_shares must cover exactly the team members that have registered public keys.",
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

  if (existing && expected_version !== undefined && existing.version !== expected_version) {
    return Response.json(
      {
        error: "version_conflict",
        server_version: existing.version,
        message: "Server has a newer version. Pull, merge, and push again.",
      },
      { status: 409 }
    );
  }

  const next_version = (existing?.version ?? 0) + 1;
  const { error } = await supabase
    .from("team_vault_blobs")
    .upsert(
      {
        team_id,
        project_id,
        encrypted_blob,
        version: next_version,
        key_shares,
      },
      { onConflict: "team_id,project_id" }
    );

  if (error) {
    return Response.json(
      {
        error: "server_error",
        message:
          "Failed to save the team vault. Try again, or email mason@ashlr.ai if this persists.",
      },
      { status: 500 }
    );
  }

  return Response.json({ version: next_version, members_covered: required.length });
}
