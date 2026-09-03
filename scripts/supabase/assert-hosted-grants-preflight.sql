\set ON_ERROR_STOP on

-- Read-only production preflight for the hosted grant migration.
--
-- Run this against the explicitly selected database before applying
-- 20260903180035_browser_and_service_role_grants.sql. Do not pass a service
-- role JWT or run it through the Data API; it intentionally verifies the
-- direct postgres migration identity and object ownership assumptions.
BEGIN TRANSACTION READ ONLY;

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
  expected_functions constant regprocedure[] := ARRAY[
    'public.update_updated_at()'::regprocedure,
    'public.prevent_user_billing_self_update()'::regprocedure,
    'public.issue_device_code(text,text,text,timestamptz)'::regprocedure,
    'public.process_stripe_billing_event(text,text,bigint,uuid,uuid,text,text,timestamptz)'::regprocedure,
    'app_private.current_user_is_team_member(uuid)'::regprocedure
  ];
  found_tables integer;
  foreign_owned_tables integer;
  rls_tables integer;
  found_functions integer;
  foreign_owned_functions integer;
BEGIN
  IF current_user <> 'postgres' THEN
    RAISE EXCEPTION
      'hosted grant preflight requires current_user postgres; found %',
      current_user;
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_roles
    WHERE rolname = 'service_role'
      AND rolbypassrls
  ) THEN
    RAISE EXCEPTION 'service_role must exist and retain BYPASSRLS';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_roles
    WHERE rolname IN ('anon', 'authenticated')
      AND rolbypassrls
  ) THEN
    RAISE EXCEPTION 'anon and authenticated must not bypass RLS';
  END IF;

  SELECT
    count(*),
    count(*) FILTER (WHERE owner.rolname <> 'postgres'),
    count(*) FILTER (WHERE relation.relrowsecurity)
  INTO found_tables, foreign_owned_tables, rls_tables
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
      'expected % postgres-owned Phantom tables; found %, with % foreign-owned',
      cardinality(expected_tables),
      found_tables,
      foreign_owned_tables;
  END IF;
  IF rls_tables <> cardinality(expected_tables) THEN
    RAISE EXCEPTION
      'expected RLS on % Phantom tables; found %',
      cardinality(expected_tables),
      rls_tables;
  END IF;

  SELECT
    count(*),
    count(*) FILTER (WHERE owner.rolname <> 'postgres')
  INTO found_functions, foreign_owned_functions
  FROM pg_catalog.pg_proc AS function
  JOIN pg_catalog.pg_roles AS owner
    ON owner.oid = function.proowner
  WHERE function.oid = ANY (expected_functions);

  IF found_functions <> cardinality(expected_functions)
    OR foreign_owned_functions <> 0 THEN
    RAISE EXCEPTION
      'expected % postgres-owned Phantom functions; found %, with % foreign-owned',
      cardinality(expected_functions),
      found_functions,
      foreign_owned_functions;
  END IF;

  -- The migration changes defaults only for objects later created by postgres.
  -- Fail if another creator has a public-schema default grant that would reopen
  -- Data API access outside that controlled default ACL.
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_default_acl AS defaults
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = defaults.defaclnamespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(defaults.defaclacl) AS privilege
    WHERE namespace.nspname = 'public'
      AND defaults.defaclrole <> 'postgres'::regrole
      AND (
        CASE
          WHEN privilege.grantee = 0 THEN 'public'
          ELSE pg_catalog.pg_get_userbyid(privilege.grantee)
        END
      ) = ANY (ARRAY['public', 'anon', 'authenticated', 'service_role'])
  ) THEN
    RAISE EXCEPTION
      'a non-postgres owner has a public-schema default Data API grant';
  END IF;
END
$$;

ROLLBACK;
