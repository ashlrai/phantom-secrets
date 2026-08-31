-- Harden personal vault writes and remove recursive team-member RLS checks.
--
-- Personal and team vault mutations must pass through the service-role API
-- routes so plan gates, size limits, key-share checks, and CAS semantics are
-- enforced in one place. Browser clients keep read access to their own data.

-- Private helper schema for RLS functions. This schema is not part of the
-- exposed API schemas; authenticated needs USAGE only so policies can call it.
CREATE SCHEMA IF NOT EXISTS app_private;
REVOKE ALL ON SCHEMA app_private FROM PUBLIC;
GRANT USAGE ON SCHEMA app_private TO authenticated;

CREATE OR REPLACE FUNCTION app_private.current_user_is_team_member(p_team_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT (SELECT auth.uid()) IS NOT NULL
    AND EXISTS (
      SELECT 1
      FROM public.team_members tm
      WHERE tm.team_id = p_team_id
        AND tm.user_id = (SELECT auth.uid())
    );
$$;

REVOKE ALL ON FUNCTION app_private.current_user_is_team_member(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_private.current_user_is_team_member(uuid) TO authenticated;

COMMENT ON FUNCTION app_private.current_user_is_team_member(uuid)
  IS 'RLS helper that checks team membership without recursively applying team_members policies.';
DROP FUNCTION IF EXISTS app_private.current_user_can_manage_team(uuid);

-- Personal vault rows remain readable by their owner, but direct browser
-- writes are denied. Service-role API routes bypass RLS and retain write access.
DROP POLICY IF EXISTS vault_blobs_read_own ON public.vault_blobs;
DROP POLICY IF EXISTS vault_blobs_insert_own ON public.vault_blobs;
DROP POLICY IF EXISTS vault_blobs_update_own ON public.vault_blobs;
DROP POLICY IF EXISTS vault_blobs_delete_own ON public.vault_blobs;

CREATE POLICY vault_blobs_read_own ON public.vault_blobs
  FOR SELECT
  TO authenticated
  USING (
    (SELECT auth.uid()) IS NOT NULL
    AND user_id = (SELECT auth.uid())
  );

REVOKE INSERT, UPDATE, DELETE ON TABLE public.vault_blobs FROM anon, authenticated;

-- Replace self-referential team policies with private helper-backed policies.
DROP POLICY IF EXISTS teams_member_read ON public.teams;
DROP POLICY IF EXISTS teams_owner_write ON public.teams;
DROP POLICY IF EXISTS team_members_read ON public.team_members;
DROP POLICY IF EXISTS team_members_admin_write ON public.team_members;
DROP POLICY IF EXISTS team_vault_blobs_member ON public.team_vault_blobs;
DROP POLICY IF EXISTS team_vault_blobs_member_read ON public.team_vault_blobs;

CREATE POLICY teams_member_read ON public.teams
  FOR SELECT
  TO authenticated
  USING (app_private.current_user_is_team_member(id));

CREATE POLICY team_members_read ON public.team_members
  FOR SELECT
  TO authenticated
  USING (app_private.current_user_is_team_member(team_id));

CREATE POLICY team_vault_blobs_member_read ON public.team_vault_blobs
  FOR SELECT
  TO authenticated
  USING (app_private.current_user_is_team_member(team_id));

-- All team mutations remain service-role API operations. This preserves plan,
-- entitlement, role, input, membership-removal, and vault-rotation controls.
REVOKE INSERT, UPDATE, DELETE ON TABLE public.teams FROM anon, authenticated;
REVOKE INSERT, UPDATE, DELETE ON TABLE public.team_members FROM anon, authenticated;
REVOKE INSERT, UPDATE, DELETE ON TABLE public.team_vault_blobs FROM anon, authenticated;
