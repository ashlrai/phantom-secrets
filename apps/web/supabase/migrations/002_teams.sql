-- Phantom Pro — Team Vaults Schema
-- Four tables: teams, team_members, team_vault_blobs, team_key_shares
-- All with Row Level Security enabled

-- ── teams ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.teams (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  owner_id uuid REFERENCES public.users(id) ON DELETE CASCADE NOT NULL,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

-- ── team_members ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.team_members (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id uuid REFERENCES public.teams(id) ON DELETE CASCADE NOT NULL,
  user_id uuid REFERENCES public.users(id) ON DELETE CASCADE NOT NULL,
  role text NOT NULL DEFAULT 'member', -- 'owner', 'admin', 'member'
  invited_by uuid REFERENCES public.users(id),
  joined_at timestamptz DEFAULT now(),
  UNIQUE(team_id, user_id)
);

-- ── team_vault_blobs (shared encrypted vaults) ──────────────────────────────
-- Uses envelope encryption: vault encrypted with team key,
-- team key encrypted per-member with their personal key
CREATE TABLE IF NOT EXISTS public.team_vault_blobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id uuid REFERENCES public.teams(id) ON DELETE CASCADE NOT NULL,
  project_id text NOT NULL,
  encrypted_blob text NOT NULL,
  version bigint NOT NULL DEFAULT 1,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now(),
  UNIQUE(team_id, project_id)
);

-- ── team_key_shares (per-member encrypted team key) ──────────────────────────
CREATE TABLE IF NOT EXISTS public.team_key_shares (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id uuid REFERENCES public.teams(id) ON DELETE CASCADE NOT NULL,
  user_id uuid REFERENCES public.users(id) ON DELETE CASCADE NOT NULL,
  encrypted_team_key text NOT NULL, -- Team key encrypted with user's personal key
  created_at timestamptz DEFAULT now(),
  UNIQUE(team_id, user_id)
);

-- ── Row Level Security ───────────────────────────────────────────────────────
ALTER TABLE public.teams ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.team_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.team_vault_blobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.team_key_shares ENABLE ROW LEVEL SECURITY;

-- Teams: members can read, owner can modify
CREATE POLICY teams_member_read ON public.teams FOR SELECT
  USING (EXISTS (SELECT 1 FROM public.team_members WHERE team_id = teams.id AND user_id = auth.uid()));
CREATE POLICY teams_owner_write ON public.teams FOR ALL
  USING (owner_id = auth.uid());

-- Team members: members can see other members
CREATE POLICY team_members_read ON public.team_members FOR SELECT
  USING (EXISTS (SELECT 1 FROM public.team_members tm WHERE tm.team_id = team_members.team_id AND tm.user_id = auth.uid()));
CREATE POLICY team_members_admin_write ON public.team_members FOR ALL
  USING (EXISTS (SELECT 1 FROM public.team_members tm WHERE tm.team_id = team_members.team_id AND tm.user_id = auth.uid() AND tm.role IN ('owner', 'admin')));

-- Team vaults: team members can read/write
CREATE POLICY team_vault_blobs_member ON public.team_vault_blobs FOR ALL
  USING (EXISTS (SELECT 1 FROM public.team_members WHERE team_id = team_vault_blobs.team_id AND user_id = auth.uid()));

-- Team key shares: users can read their own shares
CREATE POLICY team_key_shares_own ON public.team_key_shares FOR SELECT
  USING (user_id = auth.uid());

-- ── Indexes ──────────────────────────────────────────────────────────────────
CREATE INDEX ON public.team_members(team_id);
CREATE INDEX ON public.team_members(user_id);
CREATE INDEX ON public.team_vault_blobs(team_id, project_id);

-- ── updated_at triggers ──────────────────────────────────────────────────────
CREATE TRIGGER teams_updated_at BEFORE UPDATE ON public.teams
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER team_vault_blobs_updated_at BEFORE UPDATE ON public.team_vault_blobs
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();
