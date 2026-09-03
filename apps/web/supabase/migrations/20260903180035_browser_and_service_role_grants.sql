-- Make the hosted Data API surface explicit before commissioning. Supabase's
-- current defaults no longer guarantee automatic grants for new objects, and
-- older projects may still retain broad grants. Reset only Phantom-owned
-- objects, then grant back the operations exercised by the checked-in browser
-- and server clients. Row-level policies remain the authorization boundary.

BEGIN;

-- Keep future public objects closed until a reviewed migration grants a route
-- the exact operation it needs. These are the defaults used by migrations run
-- as postgres; they do not modify any Supabase-managed schema.
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  REVOKE ALL ON TABLES FROM PUBLIC, anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  REVOKE ALL ON SEQUENCES FROM PUBLIC, anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  REVOKE ALL ON FUNCTIONS FROM PUBLIC, anon, authenticated, service_role;

-- Remove legacy/default Data API privileges from every Phantom table. PUBLIC
-- is included because a grant inherited through PUBLIC would otherwise defeat
-- a role-specific revoke.
REVOKE ALL ON TABLE
  public.users,
  public.device_tokens,
  public.vault_blobs,
  public.teams,
  public.team_members,
  public.team_vault_blobs,
  public.team_key_shares,
  public.stripe_processed_events,
  public.platform_tokens,
  public.stripe_subscription_users,
  public.device_auth_rate_limits
FROM PUBLIC, anon, authenticated, service_role;

-- Schema reachability is explicit for the two Data API roles that have an
-- object grant below. anon can resolve the schema through Supabase defaults,
-- but has no privilege on any Phantom table or RPC.
GRANT USAGE ON SCHEMA public TO authenticated, service_role;

-- Browser dashboard queries are read-only. Existing RLS policies restrict
-- users and personal vaults to auth.uid(), and team rows to current members.
GRANT SELECT ON TABLE
  public.users,
  public.vault_blobs,
  public.teams,
  public.team_members
TO authenticated;

-- Server routes use a service-role client. Grant the smallest operation set
-- present in those routes; internal billing/rate-limit tables are reachable
-- only inside the existing SECURITY DEFINER RPCs below.
GRANT SELECT, INSERT, UPDATE ON TABLE public.users TO service_role;
GRANT SELECT, UPDATE ON TABLE public.device_tokens TO service_role;
GRANT SELECT, INSERT, UPDATE ON TABLE public.vault_blobs TO service_role;
GRANT SELECT, INSERT, DELETE ON TABLE public.teams TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.team_members TO service_role;
GRANT SELECT, INSERT, UPDATE ON TABLE public.team_vault_blobs TO service_role;

-- Prevent trigger helpers from becoming callable Data API RPCs. The two
-- intentional server RPCs remain service-role-only.
REVOKE ALL ON FUNCTION public.update_updated_at()
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.prevent_user_billing_self_update()
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.issue_device_code(text, text, text, timestamptz)
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.process_stripe_billing_event(
  text, text, bigint, uuid, uuid, text, text, timestamptz
) FROM PUBLIC, anon, authenticated, service_role;

GRANT EXECUTE ON FUNCTION public.issue_device_code(
  text, text, text, timestamptz
) TO service_role;
GRANT EXECUTE ON FUNCTION public.process_stripe_billing_event(
  text, text, bigint, uuid, uuid, text, text, timestamptz
) TO service_role;

COMMIT;
