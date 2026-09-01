import { requireAuth } from "@/lib/auth";
import { requireHostedService } from "@/lib/commissioning";
import { readBoundedJsonObject, requestBodyErrorResponse } from "@/lib/http-body";
import { createServiceClient } from "@/lib/supabase-server";

const MAX_PUBLIC_KEY_BODY_BYTES = 4_096;

/**
 * GET /api/v1/teams/:team_id/key — List every team member's user_id
 * and (if registered) public_key. Used by `phantom team vault push`
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
  const commissioningGate = requireHostedService("teams");
  if (commissioningGate) return commissioningGate;

  const authResult = await requireAuth(req);
  if (authResult instanceof Response) return authResult;
  const { team_id } = await params;

  let body: { public_key?: string };
  try {
    body = await readBoundedJsonObject(req, MAX_PUBLIC_KEY_BODY_BYTES);
  } catch (error) {
    return requestBodyErrorResponse(error);
  }
  const pk = body.public_key;
  if (!pk || typeof pk !== "string") {
    return Response.json(
      { error: "public_key required" },
      { status: 400 }
    );
  }
  // X25519 public keys are exactly 32 bytes encoded as canonical padded base64.
  // A length-only check lets malformed shares poison future team-vault pushes.
  let decoded: Buffer;
  try {
    decoded = Buffer.from(pk, "base64");
  } catch {
    decoded = Buffer.alloc(0);
  }
  if (
    !/^[A-Za-z0-9+/]{43}=$/.test(pk) ||
    decoded.length !== 32 ||
    decoded.toString("base64") !== pk
  ) {
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
