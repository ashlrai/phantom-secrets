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
  found_columns integer;
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

  SELECT count(*)
  INTO found_columns
  FROM pg_catalog.pg_attribute AS attribute
  JOIN pg_catalog.pg_class AS relation
    ON relation.oid = attribute.attrelid
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = relation.relnamespace
  WHERE namespace.nspname = 'public'
    AND relation.relname = ANY (expected_tables)
    AND relation.relkind IN ('r', 'p')
    AND attribute.attnum > 0
    AND NOT attribute.attisdropped;

  IF found_columns <> 84 THEN
    RAISE EXCEPTION
      'hosted grant migration expected 84 reviewed columns; found %',
      found_columns;
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_namespace AS namespace
    JOIN pg_catalog.pg_roles AS owner
      ON owner.oid = namespace.nspowner
    WHERE namespace.nspname = 'app_private'
      AND owner.rolname = 'postgres'
  ) THEN
    RAISE EXCEPTION
      'hosted grant migration requires postgres-owned app_private schema';
  END IF;
END
$$;

-- Keep future public objects closed until a reviewed migration grants a route
-- the exact operation it needs. These are the defaults used by migrations run
-- as postgres; they do not modify any Supabase-managed schema.
--
-- PostgreSQL's built-in function default is global PUBLIC EXECUTE. A
-- schema-scoped revoke cannot subtract that global grant, so this intentionally
-- changes every future function created by postgres in every schema. Callers
-- must explicitly grant EXECUTE on each reviewed function after creation. This
-- does not change existing functions or functions owned by another role.
ALTER DEFAULT PRIVILEGES FOR ROLE postgres
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
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

-- Table-level revokes do not remove column ACLs. Enumerate every reviewed live
-- column and clear the four PostgreSQL privileges that can be granted at column
-- scope. Dynamic identifiers come only from the system catalogs and are quoted.
DO $$
DECLARE
  target record;
  privilege_name text;
BEGIN
  FOR target IN
    SELECT
      format('%I.%I', namespace.nspname, relation.relname) AS table_name,
      string_agg(
        format('%I', attribute.attname),
        ', '
        ORDER BY attribute.attnum
      ) AS column_names
    FROM pg_catalog.pg_attribute AS attribute
    JOIN pg_catalog.pg_class AS relation
      ON relation.oid = attribute.attrelid
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'public'
      AND relation.relname = ANY (ARRAY[
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
      ])
      AND relation.relkind IN ('r', 'p')
      AND attribute.attnum > 0
      AND NOT attribute.attisdropped
    GROUP BY namespace.nspname, relation.relname
  LOOP
    FOREACH privilege_name IN ARRAY ARRAY[
      'SELECT', 'INSERT', 'UPDATE', 'REFERENCES'
    ]
    LOOP
      EXECUTE format(
        'REVOKE %s (%s) ON TABLE %s FROM PUBLIC, anon, authenticated, service_role',
        privilege_name,
        target.column_names,
        target.table_name
      );
    END LOOP;
  END LOOP;
END
$$;

-- Schema reachability is explicit for the two Data API roles that have an
-- object grant below. anon can resolve the schema through Supabase defaults,
-- but has no privilege on any Phantom table or RPC.
REVOKE ALL ON SCHEMA public FROM anon, authenticated, service_role;
GRANT USAGE ON SCHEMA public TO authenticated, service_role;
REVOKE ALL ON SCHEMA app_private FROM anon, authenticated, service_role;
GRANT USAGE ON SCHEMA app_private TO authenticated;

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
