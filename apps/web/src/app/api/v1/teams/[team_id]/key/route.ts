import { requireAuth } from "@/lib/auth";
import { createServiceClient } from "@/lib/supabase-server";

/**
 * GET /api/v1/teams/:team_id/key — List every team member's user_id
 * and (if registered) public_key. Used by `phantom team vault push`
 * to know who to encrypt the per-vault symmetric key to.
 *
 * Members without a registered public_key are returned with public_key
 * null — they will be silently skipped from key_shares and will get a
 * 412 missing_key when they try to pull until they register.
 */
export async function GET(
  req: Request,
  { params }: { params: Promise<{ team_id: string }> }
) {
  const { team_id } = await params;
  const authResult = await requireAuth(req);
  if (authResult instanceof Response) return authResult;

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

  return Response.json({ members: members ?? [] });
}

/**
 * POST /api/v1/teams/:team_id/key — Register or update the caller's
 * X25519 public key on this team. Required before they can pull a
 * team vault that's already been pushed.
 *
 * Body: { public_key: string }  // base64-encoded 32 bytes
 */
export async function POST(
  req: Request,
  { params }: { params: Promise<{ team_id: string }> }
) {
  const { team_id } = await params;
  const authResult = await requireAuth(req);
  if (authResult instanceof Response) return authResult;

  const body = (await req.json()) as { public_key?: string };
  const pk = body.public_key;
  if (!pk || typeof pk !== "string") {
    return Response.json(
      { error: "public_key required" },
      { status: 400 }
    );
  }
  // 32 bytes base64 = 44 chars (with padding). Reject obvious garbage.
  if (pk.length < 40 || pk.length > 100) {
    return Response.json(
      { error: "public_key must be base64-encoded 32 bytes" },
      { status: 400 }
    );
  }

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
