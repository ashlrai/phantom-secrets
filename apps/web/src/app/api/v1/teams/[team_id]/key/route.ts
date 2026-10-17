import { requireAuth } from "@/lib/auth";
import { requireHostedService } from "@/lib/commissioning";
import { readBoundedJsonObject, requestBodyErrorResponse } from "@/lib/http-body";
import { createServiceClient } from "@/lib/supabase-server";
import { algForStoredKey, CLASSIC_ALG, parseTeamKeyRegistration } from "@/lib/team-key";

const MAX_PUBLIC_KEY_BODY_BYTES = 4_096;

/**
 * GET /api/v1/teams/:team_id/key — List every team member's user_id
 * and (if registered) public_key. Used by `phantom team vault-push`
 * to know who to encrypt the per-vault symmetric key to.
 *
 * Members without a registered public_key are returned with public_key
 * null — they will be silently skipped from wrappedKeys and will get a
 * 412 missing_key when they try to pull until they register.
 */
export async function GET(
  req: Request,
  { params }: { params: Promise<{ team_id: string }> }
) {
  const commissioningGate = requireHostedService("teams");
  if (commissioningGate) return commissioningGate;

  const authResult = await requireAuth(req);
  if (authResult instanceof Response) return authResult;
  const { team_id } = await params;

  const supabase = createServiceClient();

  // Caller must be a member.
  const { data: membership } = await supabase
    .from("team_members")
    .select("id")
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

  const { data: members } = await supabase
    .from("team_members")
    .select("user_id, public_key")
    .eq("team_id", team_id);

  // Default response is unchanged for old clients: only classic 32-byte keys
  // are listed, a hybrid key shows as null (skipped, as for an unregistered
  // member). Clients that understand hybrid keys pass ?algs=all and also get
  // each member's `alg`.
  const all = new URL(req.url).searchParams.get("algs") === "all";
  const rows = (members ?? []).map((m) => {
    const alg = algForStoredKey(m.public_key);
    if (all) return { ...m, alg };
    return alg === CLASSIC_ALG ? m : { ...m, public_key: null };
  });
  return Response.json({ members: rows });
}

/**
 * POST /api/v1/teams/:team_id/key — Register or update the caller's
 * X25519 public key on this team. Required before they can pull a
 * team vault that's already been pushed.
 *
 * Body: { public_key: string }  // base64-encoded 32 bytes (classic, default)
 *       { public_key, v: 2, alg: "xwing-chacha20poly1305" }  // 1216-byte X-Wing key
 */
export async function POST(
  req: Request,
  { params }: { params: Promise<{ team_id: string }> }
) {
  const commissioningGate = requireHostedService("teams");
  if (commissioningGate) return commissioningGate;

  const authResult = await requireAuth(req);
  if (authResult instanceof Response) return authResult;
  const { team_id } = await params;

  let body: { public_key?: unknown; v?: unknown; alg?: unknown };
  try {
    body = await readBoundedJsonObject(req, MAX_PUBLIC_KEY_BODY_BYTES);
  } catch (error) {
    return requestBodyErrorResponse(error);
  }
  // Classic 32-byte X25519 by default; a 1216-byte X-Wing key only when it is
  // declared with the share format tag (see lib/team-key.ts).
  const parsed = parseTeamKeyRegistration(body);
  if (!parsed.ok) {
    return Response.json({ error: parsed.error }, { status: 400 });
  }
  const pk = body.public_key as string;

  const supabase = createServiceClient();

  // Caller must be a member of this team.
  const { data: membership } = await supabase
    .from("team_members")
    .select("id")
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

  const { error } = await supabase
    .from("team_members")
    .update({ public_key: pk })
    .eq("team_id", team_id)
    .eq("user_id", authResult.userId);

  if (error) {
    return Response.json(
      {
        error: "server_error",
        message:
          "Failed to register public key. Try again, or email mason@ashlr.ai if this persists.",
      },
      { status: 500 }
    );
  }

  return Response.json({ ok: true });
}
