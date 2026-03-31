import { requireAuth, requirePro } from "@/lib/auth";
import { createServiceClient } from "@/lib/supabase-server";

/**
 * GET /api/v1/teams — List teams the authenticated user belongs to.
 */
export async function GET(req: Request) {
  const authResult = await requireAuth(req);
  if (authResult instanceof Response) return authResult;

  const supabase = createServiceClient();

  // Get all teams this user is a member of
  const { data: memberships, error } = await supabase
    .from("team_members")
    .select("team_id, role, joined_at")
    .eq("user_id", authResult.userId);

  if (error) {
    return Response.json({ error: "Failed to fetch teams" }, { status: 500 });
  }

  if (!memberships || memberships.length === 0) {
    return Response.json({ teams: [] });
  }

  const teamIds = memberships.map((m) => m.team_id);

  const { data: teams, error: teamsError } = await supabase
    .from("teams")
    .select("id, name, owner_id, created_at")
    .in("id", teamIds);

  if (teamsError) {
    return Response.json({ error: "Failed to fetch teams" }, { status: 500 });
  }

  // Merge membership info with team info
  const result = (teams ?? []).map((team) => {
    const membership = memberships.find((m) => m.team_id === team.id);
    return {
      ...team,
      role: membership?.role,
      joined_at: membership?.joined_at,
    };
  });

  return Response.json({ teams: result });
}

/**
 * POST /api/v1/teams — Create a new team (Pro required).
 * Body: { name: string }
 */
export async function POST(req: Request) {
  const authResult = await requireAuth(req);
  if (authResult instanceof Response) return authResult;

  // Teams require Pro plan
  const proRequired = requirePro(authResult);
  if (proRequired) return proRequired;

  const body = await req.json();
  const { name } = body;

  if (!name || typeof name !== "string" || name.trim().length === 0) {
    return Response.json({ error: "name is required" }, { status: 400 });
  }

  if (name.length > 100) {
    return Response.json(
      { error: "name must be 100 characters or fewer" },
      { status: 400 }
    );
  }

  const supabase = createServiceClient();

  // Create the team
  const { data: team, error: teamError } = await supabase
    .from("teams")
    .insert({
      name: name.trim(),
      owner_id: authResult.userId,
    })
    .select("id, name, owner_id, created_at")
    .single();

  if (teamError) {
    return Response.json({ error: "Failed to create team" }, { status: 500 });
  }

  // Add the creator as an owner member
  const { error: memberError } = await supabase.from("team_members").insert({
    team_id: team.id,
    user_id: authResult.userId,
    role: "owner",
  });

  if (memberError) {
    // Rollback team creation on member insert failure
    await supabase.from("teams").delete().eq("id", team.id);
    return Response.json({ error: "Failed to create team" }, { status: 500 });
  }

  return Response.json({ team }, { status: 201 });
}
