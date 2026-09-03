-- Make the hosted Data API surface explicit before commissioning. Supabase's
-- current defaults no longer guarantee automatic grants for new objects, and
-- older projects may still retain broad grants. Reset only Phantom-owned
-- objects, then grant back the operations exercised by the checked-in browser
-- and server clients. RLS is the authenticated-browser row boundary;
-- service_role bypasses RLS, so server-route authentication, authorization,
-- predicates, validation, and commissioning gates remain its row boundary.

BEGIN;

-- Fail before changing privileges if this database does not match the owner
-- assumptions used below. The matching read-only operator preflight lives at
-- scripts/supabase/assert-hosted-grants-preflight.sql.
DO $$
DECLARE
  expected_tables constant text[] := ARRAY[
    'users',
    'device_tokens',
    'vault_blobs',
    'teams',
    'team_members',
    'team_vault_blobs',
    'team_key_shares',
    'stripe_processed_events',
    'platform_tokens',
    'stripe_subscription_users',
    'device_auth_rate_limits'
  ];
  found_tables integer;
  foreign_owned_tables integer;
BEGIN
  IF current_user <> 'postgres' THEN
    RAISE EXCEPTION
      'hosted grant migration must run as postgres; current_user is %',
      current_user;
  END IF;

  SELECT count(*), count(*) FILTER (WHERE owner.rolname <> 'postgres')
  INTO found_tables, foreign_owned_tables
  FROM pg_catalog.pg_class AS relation
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = relation.relnamespace
  JOIN pg_catalog.pg_roles AS owner
    ON owner.oid = relation.relowner
  WHERE namespace.nspname = 'public'
    AND relation.relkind IN ('r', 'p')
    AND relation.relname = ANY (expected_tables);

  IF found_tables <> cardinality(expected_tables) OR foreign_owned_tables <> 0 THEN
    RAISE EXCEPTION
      'hosted grant migration expected % postgres-owned tables; found %, with % foreign-owned',
      cardinality(expected_tables),
      found_tables,
      foreign_owned_tables;
  END IF;
END
$$;

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
