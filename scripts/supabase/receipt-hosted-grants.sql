\set ON_ERROR_STOP on

-- Read-only post-apply receipt for the hosted Data API authority boundary.
-- Run with the direct postgres connection immediately after applying migrations:
-- psql "$DATABASE_URL" -X --file scripts/supabase/receipt-hosted-grants.sql
-- The command exits nonzero on any effective ACL drift and emits one value-free
-- JSON receipt only after every assertion succeeds.
BEGIN TRANSACTION READ ONLY;

DO $$
DECLARE
  expected_roles constant text[] := ARRAY[
    'anon', 'authenticated', 'service_role'
  ];
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
  expected_privileges constant text[] := ARRAY[
    'SELECT', 'INSERT', 'UPDATE', 'DELETE',
    'TRUNCATE', 'REFERENCES', 'TRIGGER', 'MAINTAIN'
  ];
  matrix_cells integer;
  matrix_mismatches integer;
  matrix_distinct_tables integer;
  matrix_reviewed_tables integer;
  function_cells integer;
  function_mismatches integer;
  rls_tables integer;
BEGIN
  IF current_user <> 'postgres' THEN
    RAISE EXCEPTION
      'hosted grant receipt requires current_user postgres; found %',
      current_user;
  END IF;

  IF cardinality(expected_roles) <> 3
    OR cardinality(expected_tables) <> 11
    OR cardinality(expected_privileges) <> 8 THEN
    RAISE EXCEPTION
      'hosted grant receipt matrix cardinality changed: roles %, tables %, privileges %',
      cardinality(expected_roles),
      cardinality(expected_tables),
      cardinality(expected_privileges);
  END IF;

  WITH roles(role_name) AS (
    SELECT unnest(expected_roles)
  ),
  tables(table_name, authenticated_privileges, service_privileges) AS (
    VALUES
      ('users', ARRAY['SELECT'], ARRAY['SELECT', 'INSERT', 'UPDATE']),
      ('device_tokens', ARRAY[]::text[], ARRAY['SELECT', 'UPDATE']),
      ('vault_blobs', ARRAY['SELECT'], ARRAY['SELECT', 'INSERT', 'UPDATE']),
      ('teams', ARRAY['SELECT'], ARRAY['SELECT', 'INSERT', 'DELETE']),
      ('team_members', ARRAY['SELECT'], ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE']),
      ('team_vault_blobs', ARRAY[]::text[], ARRAY['SELECT', 'INSERT', 'UPDATE']),
      ('team_key_shares', ARRAY[]::text[], ARRAY[]::text[]),
      ('stripe_processed_events', ARRAY[]::text[], ARRAY[]::text[]),
      ('platform_tokens', ARRAY[]::text[], ARRAY[]::text[]),
      ('stripe_subscription_users', ARRAY[]::text[], ARRAY[]::text[]),
      ('device_auth_rate_limits', ARRAY[]::text[], ARRAY[]::text[])
  ),
  privileges(privilege_name) AS (
    SELECT unnest(expected_privileges)
  ),
  matrix AS (
    SELECT
      roles.role_name,
      tables.table_name,
      privileges.privilege_name,
      CASE roles.role_name
        WHEN 'authenticated' THEN
          privileges.privilege_name = ANY (tables.authenticated_privileges)
        WHEN 'service_role' THEN
          privileges.privilege_name = ANY (tables.service_privileges)
        ELSE false
      END AS expected,
      has_table_privilege(
        roles.role_name,
        'public.' || tables.table_name,
        privileges.privilege_name
      ) AS actual
    FROM roles
    CROSS JOIN tables
    CROSS JOIN privileges
  )
  SELECT
    count(*),
    count(*) FILTER (WHERE actual IS DISTINCT FROM expected),
    count(DISTINCT table_name),
    count(DISTINCT table_name) FILTER (
      WHERE table_name = ANY (expected_tables)
    )
  INTO
    matrix_cells,
    matrix_mismatches,
    matrix_distinct_tables,
    matrix_reviewed_tables
  FROM matrix;

  IF matrix_cells <> 264
    OR matrix_mismatches <> 0
    OR matrix_distinct_tables <> 11
    OR matrix_reviewed_tables <> 11 THEN
    RAISE EXCEPTION
      'effective table ACL receipt failed: cells %, mismatches %, distinct tables %, reviewed tables %',
      matrix_cells,
      matrix_mismatches,
      matrix_distinct_tables,
      matrix_reviewed_tables;
  END IF;

  WITH roles(role_name) AS (
    SELECT unnest(expected_roles)
  ),
  functions(function_name, authenticated_execute, service_execute) AS (
    VALUES
      ('public.update_updated_at()', false, false),
      ('public.prevent_user_billing_self_update()', false, false),
      ('public.issue_device_code(text,text,text,timestamptz)', false, true),
      ('public.process_stripe_billing_event(text,text,bigint,uuid,uuid,text,text,timestamptz)', false, true),
      ('app_private.current_user_is_team_member(uuid)', true, false)
  )
  SELECT
    count(*),
    count(*) FILTER (
      WHERE has_function_privilege(
        roles.role_name,
        functions.function_name,
        'EXECUTE'
      ) IS DISTINCT FROM (
        CASE roles.role_name
          WHEN 'authenticated' THEN functions.authenticated_execute
          WHEN 'service_role' THEN functions.service_execute
          ELSE false
        END
      )
    )
  INTO function_cells, function_mismatches
  FROM roles
  CROSS JOIN functions;

  IF function_cells <> 15 OR function_mismatches <> 0 THEN
    RAISE EXCEPTION
      'effective function ACL receipt failed: cells %, mismatches %',
      function_cells,
      function_mismatches;
  END IF;

  SELECT count(*)
  INTO rls_tables
  FROM pg_catalog.pg_class AS relation
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = relation.relnamespace
  WHERE namespace.nspname = 'public'
    AND relation.relname = ANY (expected_tables)
    AND relation.relkind IN ('r', 'p')
    AND relation.relrowsecurity;

  IF rls_tables <> cardinality(expected_tables) THEN
    RAISE EXCEPTION
      'hosted grant receipt expected RLS on % tables; found %',
      cardinality(expected_tables),
      rls_tables;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_default_acl AS defaults
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = defaults.defaclnamespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(defaults.defaclacl) AS privilege
    WHERE namespace.nspname = 'public'
      AND (
        CASE
          WHEN privilege.grantee = 0 THEN 'public'
          ELSE pg_catalog.pg_get_userbyid(privilege.grantee)
        END
      ) = ANY (ARRAY['public', 'anon', 'authenticated', 'service_role'])
  ) THEN
    RAISE EXCEPTION
      'hosted grant receipt found a default public-schema Data API grant';
  END IF;

  IF pg_catalog.has_schema_privilege('anon', 'public', 'CREATE')
    OR pg_catalog.has_schema_privilege('authenticated', 'public', 'CREATE')
    OR pg_catalog.has_schema_privilege('service_role', 'public', 'CREATE') THEN
    RAISE EXCEPTION
      'hosted grant receipt found Data API object-creation authority';
  END IF;
END
$$;

SELECT jsonb_build_object(
  'contract', 'phantom-hosted-data-api-authority-v1',
  'roles', 3,
  'tables', 11,
  'table_privileges', 8,
  'effective_table_acl_cells', 264,
  'table_acl_mismatches', 0,
  'effective_function_acl_cells', 15,
  'function_acl_mismatches', 0,
  'rls_tables', 11,
  'default_acl_grants', 0
) AS hosted_grants_receipt;

ROLLBACK;
