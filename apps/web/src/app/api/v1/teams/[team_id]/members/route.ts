import { requireAuth, requirePro } from "@/lib/auth";
import { readBoundedJsonObject, requestBodyErrorResponse } from "@/lib/http-body";
import { createServiceClient } from "@/lib/supabase-server";

const MAX_TEAM_MEMBER_BODY_BYTES = 8_192;

type AddMemberBody = {
  user_id?: string;
  github_login?: string;
  role?: "admin" | "member";
};

interface RouteContext {
  params: Promise<{ team_id: string }>;
}

/**
 * GET /api/v1/teams/:team_id/members — List members of a team.
 * Requires the caller to be a member of the team.
 */
export async function GET(req: Request, context: RouteContext) {
  const authResult = await requireAuth(req);
  if (authResult instanceof Response) return authResult;

  const { team_id } = await context.params;

  const supabase = createServiceClient();

  // Verify caller is a member of this team
  const { data: callerMembership } = await supabase
    .from("team_members")
    .select("role")
    .eq("team_id", team_id)
    .eq("user_id", authResult.userId)
    .single();

  if (!callerMembership) {
    return Response.json({ error: "not found" }, { status: 404 });
  }

  // Fetch all members with user info
  const { data: members, error } = await supabase
    .from("team_members")
    .select("id, user_id, role, invited_by, joined_at, public_key")
    .eq("team_id", team_id);

  if (error) {
    return Response.json(
      { error: "Failed to fetch members" },
      { status: 500 }
    );
  }

  if (!members || members.length === 0) {
    return Response.json({ members: [] });
  }

  // Enrich with user details
  const userIds = members.map((m) => m.user_id);
  const { data: users } = await supabase
    .from("users")
    .select("id, github_login, email")
    .in("id", userIds);

  const usersMap = new Map(
    (users ?? []).map((u) => [u.id, { github_login: u.github_login, email: u.email }])
  );

  const enrichedMembers = members.map((m) => ({
    id: m.id,
    user_id: m.user_id,
    role: m.role,
    invited_by: m.invited_by,
    joined_at: m.joined_at,
    has_public_key: Boolean(m.public_key),
    ...(usersMap.get(m.user_id) ?? {}),
  }));

  return Response.json({ members: enrichedMembers });
}

/**
 * POST /api/v1/teams/:team_id/members — Invite a member to the team.
 * Requires the caller to be an owner or admin of the team.
 * Body: { user_id?: string, github_login?: string, role?: "admin" | "member" }
 */
export async function POST(req: Request, context: RouteContext) {
  const authResult = await requireAuth(req);
  if (authResult instanceof Response) return authResult;

  // Teams require Pro plan
  const proRequired = requirePro(authResult);
  if (proRequired) return proRequired;

  const { team_id } = await context.params;

  const supabase = createServiceClient();

  // Verify caller is an owner or admin
  const { data: callerMembership } = await supabase
    .from("team_members")
    .select("role")
    .eq("team_id", team_id)
    .eq("user_id", authResult.userId)
    .single();

  if (!callerMembership || !["owner", "admin"].includes(callerMembership.role)) {
    return Response.json({ error: "forbidden" }, { status: 403 });
  }

  let body: AddMemberBody;
  try {
    body = await readBoundedJsonObject(req, MAX_TEAM_MEMBER_BODY_BYTES);
  } catch (error) {
    return requestBodyErrorResponse(error);
  }
  const { user_id, github_login, role } = body;

  const memberRole = role ?? "member";
  if (!["admin", "member"].includes(memberRole)) {
    return Response.json(
      { error: "role must be 'admin' or 'member'" },
      { status: 400 }
    );
  }

  let targetUserId: string | null = null;

  if (typeof user_id === "string" && user_id.trim()) {
    const { data: targetUser } = await supabase
      .from("users")
      .select("id")
      .eq("id", user_id.trim())
      .single();

    if (!targetUser) {
      return Response.json({ error: "user not found" }, { status: 404 });
    }

    targetUserId = targetUser.id;
  } else if (typeof github_login === "string" && github_login.trim()) {
    const normalizedLogin = github_login.trim().replace(/^@+/, "").toLowerCase();

    if (!/^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$/.test(normalizedLogin)) {
      return Response.json(
        { error: "github_login is invalid" },
        { status: 400 }
      );
    }

    const { data: targetUsers, error: targetError } = await supabase
      .from("users")
      .select("id")
      .eq("github_login_normalized", normalizedLogin)
      .limit(2);

    if (targetError) {
      return Response.json(
        { error: "Failed to resolve GitHub user" },
        { status: 500 }
      );
    }

    if (!targetUsers || targetUsers.length === 0) {
      return Response.json(
        { error: "GitHub user not found; invitee must sign in to Phantom first" },
        { status: 404 }
      );
    }

    if (targetUsers.length > 1) {
      return Response.json(
        { error: "GitHub login matches multiple Phantom users" },
        { status: 409 }
      );
    }

    targetUserId = targetUsers[0].id;
  } else {
    return Response.json(
      { error: "user_id or github_login is required" },
      { status: 400 }
    );
  }

  // Add member
  const { data: member, error } = await supabase
    .from("team_members")
    .insert({
      team_id,
      user_id: targetUserId,
      role: memberRole,
      invited_by: authResult.userId,
    })
    .select("id, team_id, user_id, role, invited_by, joined_at")
    .single();

  if (error) {
    if (error.code === "23505") {
      return Response.json(
        { error: "user is already a member of this team" },
        { status: 409 }
      );
    }
    return Response.json(
      { error: "Failed to add member" },
      { status: 500 }
    );
  }

  return Response.json({ member }, { status: 201 });
}
