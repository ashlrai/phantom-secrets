import { requireAuth, requirePro } from "@/lib/auth";
import { createServiceClient } from "@/lib/supabase-server";

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
    .select("id, user_id, role, invited_by, joined_at")
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
    ...m,
    ...(usersMap.get(m.user_id) ?? {}),
  }));

  return Response.json({ members: enrichedMembers });
}

/**
 * POST /api/v1/teams/:team_id/members — Invite a member to the team.
 * Requires the caller to be an owner or admin of the team.
 * Body: { user_id: string, role?: "admin" | "member" }
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

  const body = await req.json();
  const { user_id, role } = body;

  if (!user_id || typeof user_id !== "string") {
    return Response.json({ error: "user_id is required" }, { status: 400 });
  }

  const memberRole = role ?? "member";
  if (!["admin", "member"].includes(memberRole)) {
    return Response.json(
      { error: "role must be 'admin' or 'member'" },
      { status: 400 }
    );
  }

  // Cannot invite as owner — there can only be one owner (the creator)
  if (memberRole === "owner") {
    return Response.json(
      { error: "cannot assign owner role via invitation" },
      { status: 400 }
    );
  }

  // Verify the target user exists
  const { data: targetUser } = await supabase
    .from("users")
    .select("id")
    .eq("id", user_id)
    .single();

  if (!targetUser) {
    return Response.json({ error: "user not found" }, { status: 404 });
  }

  // Add member
  const { data: member, error } = await supabase
    .from("team_members")
    .insert({
      team_id,
      user_id,
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
