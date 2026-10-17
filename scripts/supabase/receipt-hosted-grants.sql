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
  expected_column_privileges constant text[] := ARRAY[
    'SELECT', 'INSERT', 'UPDATE', 'REFERENCES'
  ];
  expected_functions constant text[] := ARRAY[
    'public.update_updated_at()',
    'public.prevent_user_billing_self_update()',
    'public.issue_device_code(text,text,text,timestamptz)',
    'public.process_stripe_billing_event(text,text,bigint,uuid,uuid,text,text,timestamptz)',
    'app_private.current_user_is_team_member(uuid)'
  ];
  matrix_cells integer;
  matrix_mismatches integer;
  matrix_distinct_tables integer;
  matrix_reviewed_tables integer;
  table_grant_options integer;
  reviewed_columns integer;
  column_acl_cells integer;
  column_acl_mismatches integer;
  function_cells integer;
  function_mismatches integer;
  function_distinct_names integer;
  function_reviewed_names integer;
  function_grant_options integer;
  rls_tables integer;
  global_default_grants integer;
  public_default_grants integer;
  app_private_schema_owner name;
BEGIN
  IF current_user <> 'postgres' THEN
    RAISE EXCEPTION
      'hosted grant receipt requires current_user postgres; found %',
      current_user;
  END IF;

  IF cardinality(expected_roles) <> 3
    OR cardinality(expected_tables) <> 11
    OR cardinality(expected_privileges) <> 8
    OR cardinality(expected_column_privileges) <> 4
    OR cardinality(expected_functions) <> 5 THEN
    RAISE EXCEPTION
      'hosted grant receipt matrix cardinality changed: roles %, tables %, table privileges %, column privileges %, functions %',
      cardinality(expected_roles),
      cardinality(expected_tables),
      cardinality(expected_privileges),
      cardinality(expected_column_privileges),
      cardinality(expected_functions);
  END IF;

  SELECT owner.rolname
  INTO app_private_schema_owner
  FROM pg_catalog.pg_namespace AS namespace
  JOIN pg_catalog.pg_roles AS owner
    ON owner.oid = namespace.nspowner
  WHERE namespace.nspname = 'app_private';

  IF app_private_schema_owner IS DISTINCT FROM 'postgres' THEN
    RAISE EXCEPTION
      'hosted grant receipt requires postgres-owned app_private schema; found %',
      coalesce(app_private_schema_owner, '<missing>');
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
      ) AS actual,
      has_table_privilege(
        roles.role_name,
        'public.' || tables.table_name,
        privileges.privilege_name || ' WITH GRANT OPTION'
      ) AS grantable
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
    ),
    count(*) FILTER (WHERE grantable)
  INTO
    matrix_cells,
    matrix_mismatches,
    matrix_distinct_tables,
    matrix_reviewed_tables,
    table_grant_options
  FROM matrix;

  IF matrix_cells <> 264
    OR matrix_mismatches <> 0
    OR matrix_distinct_tables <> 11
    OR matrix_reviewed_tables <> 11
    OR table_grant_options <> 0 THEN
    RAISE EXCEPTION
      'effective table ACL receipt failed: cells %, mismatches %, distinct tables %, reviewed tables %, grant options %',
      matrix_cells,
      matrix_mismatches,
      matrix_distinct_tables,
      matrix_reviewed_tables,
      table_grant_options;
  END IF;

  WITH roles(role_name) AS (
    SELECT unnest(expected_roles)
  ),
  privileges(privilege_name) AS (
    SELECT unnest(expected_column_privileges)
  ),
  columns(table_name, column_name, column_acl) AS (
    SELECT
      relation.relname,
      attribute.attname,
      attribute.attacl
    FROM pg_catalog.pg_attribute AS attribute
    JOIN pg_catalog.pg_class AS relation
      ON relation.oid = attribute.attrelid
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'public'
      AND relation.relname = ANY (expected_tables)
      AND relation.relkind IN ('r', 'p')
      AND attribute.attnum > 0
      AND NOT attribute.attisdropped
  ),
  matrix AS (
    SELECT
      roles.role_name,
      columns.table_name,
      columns.column_name,
      privileges.privilege_name,
      EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(columns.column_acl) AS acl
        WHERE (
          acl.grantee = 0
          OR pg_catalog.pg_get_userbyid(acl.grantee) = roles.role_name
        )
          AND acl.privilege_type = privileges.privilege_name
      ) AS has_column_acl
    FROM roles
    CROSS JOIN columns
    CROSS JOIN privileges
  )
  SELECT
    count(DISTINCT (table_name, column_name)),
    count(*),
    count(*) FILTER (WHERE has_column_acl)
  INTO reviewed_columns, column_acl_cells, column_acl_mismatches
  FROM matrix;

  IF reviewed_columns <> 84
    OR column_acl_cells <> 1008
    OR column_acl_mismatches <> 0 THEN
    RAISE EXCEPTION
      'column ACL receipt failed: columns %, cells %, grants %',
      reviewed_columns,
      column_acl_cells,
      column_acl_mismatches;
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
    ),
    count(DISTINCT functions.function_name),
    count(DISTINCT functions.function_name) FILTER (
      WHERE functions.function_name = ANY (expected_functions)
    ),
    count(*) FILTER (
      WHERE has_function_privilege(
        roles.role_name,
        functions.function_name,
        'EXECUTE WITH GRANT OPTION'
      )
    )
  INTO
    function_cells,
    function_mismatches,
    function_distinct_names,
    function_reviewed_names,
    function_grant_options
  FROM roles
  CROSS JOIN functions;

  IF function_cells <> 15
    OR function_mismatches <> 0
    OR function_distinct_names <> 5
    OR function_reviewed_names <> 5
    OR function_grant_options <> 0 THEN
    RAISE EXCEPTION
      'effective function ACL receipt failed: cells %, mismatches %, distinct functions %, reviewed functions %, grant options %',
      function_cells,
      function_mismatches,
      function_distinct_names,
      function_reviewed_names,
      function_grant_options;
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

  -- Global defaults are effective even when pg_default_acl has no row. In
  -- particular, acldefault('f', owner) includes PUBLIC EXECUTE. Coalescing the
  -- catalog row with acldefault prevents that implicit grant from disappearing
  -- from this receipt.
  WITH object_types(object_type) AS (
    VALUES ('r'::"char"), ('S'::"char"), ('f'::"char")
  ),
  global_defaults(object_type, acl) AS (
    SELECT
      object_types.object_type,
      coalesce(
        defaults.defaclacl,
        pg_catalog.acldefault(
          object_types.object_type,
          'postgres'::regrole
        )
      )
    FROM object_types
    LEFT JOIN pg_catalog.pg_default_acl AS defaults
      ON defaults.defaclrole = 'postgres'::regrole
      AND defaults.defaclnamespace = 0
      AND defaults.defaclobjtype = object_types.object_type
  )
  SELECT count(*)
  INTO global_default_grants
  FROM global_defaults
  CROSS JOIN LATERAL pg_catalog.aclexplode(global_defaults.acl) AS privilege
  WHERE privilege.grantee = 0
    OR pg_catalog.pg_get_userbyid(privilege.grantee) = ANY (
      ARRAY['anon', 'authenticated', 'service_role']
    );

  IF global_default_grants <> 0 THEN
    RAISE EXCEPTION
      'hosted grant receipt found % global default Data API grants',
      global_default_grants;
  END IF;

  -- Every reviewed application object is postgres-owned and the migration
  -- identity is postgres. Supabase's stock runtime seeds platform-owned
  -- supabase_admin defaults in public; they are not part of Phantom's creation
  -- path, so this receipt intentionally scopes future-object defaults to the
  -- asserted application owner instead of rejecting the platform baseline.
  SELECT count(*)
  INTO public_default_grants
  FROM pg_catalog.pg_default_acl AS defaults
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = defaults.defaclnamespace
  CROSS JOIN LATERAL pg_catalog.aclexplode(defaults.defaclacl) AS privilege
  WHERE namespace.nspname = 'public'
    AND defaults.defaclrole = 'postgres'::regrole
    AND (
      privilege.grantee = 0
      OR pg_catalog.pg_get_userbyid(privilege.grantee) = ANY (
        ARRAY['anon', 'authenticated', 'service_role']
      )
    );

  IF public_default_grants <> 0 THEN
    RAISE EXCEPTION
      'hosted grant receipt found % public-schema default Data API grants',
      public_default_grants;
  END IF;

  IF pg_catalog.has_schema_privilege('anon', 'public', 'CREATE')
    OR pg_catalog.has_schema_privilege('authenticated', 'public', 'CREATE')
    OR pg_catalog.has_schema_privilege('service_role', 'public', 'CREATE') THEN
    RAISE EXCEPTION
      'hosted grant receipt found Data API object-creation authority';
  END IF;

  IF pg_catalog.has_schema_privilege('anon', 'app_private', 'CREATE')
    OR pg_catalog.has_schema_privilege(
      'authenticated', 'app_private', 'CREATE'
    )
    OR pg_catalog.has_schema_privilege(
      'service_role', 'app_private', 'CREATE'
    ) THEN
    RAISE EXCEPTION
      'hosted grant receipt found app_private object-creation authority';
  END IF;

  IF NOT pg_catalog.has_schema_privilege(
    'authenticated', 'public', 'USAGE'
  ) OR NOT pg_catalog.has_schema_privilege(
    'service_role', 'public', 'USAGE'
  ) OR NOT pg_catalog.has_schema_privilege(
    'authenticated', 'app_private', 'USAGE'
  ) OR pg_catalog.has_schema_privilege(
    'anon', 'app_private', 'USAGE'
  ) OR pg_catalog.has_schema_privilege(
    'service_role', 'app_private', 'USAGE'
  ) THEN
    RAISE EXCEPTION
      'hosted grant receipt found schema usage drift';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_namespace AS namespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(namespace.nspacl) AS privilege
    WHERE namespace.nspname IN ('public', 'app_private')
      AND (
        privilege.grantee = 0
        OR pg_catalog.pg_get_userbyid(privilege.grantee) = ANY (
          ARRAY['anon', 'authenticated', 'service_role']
        )
      )
      AND privilege.is_grantable
  ) THEN
    RAISE EXCEPTION
      'hosted grant receipt found Data API schema WITH GRANT OPTION';
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
  'table_grant_options', 0,
  'columns', 84,
  'column_privileges', 4,
  'effective_column_acl_cells', 1008,
  'column_acl_grants', 0,
  'functions', 5,
  'effective_function_acl_cells', 15,
  'function_acl_mismatches', 0,
  'function_grant_options', 0,
  'rls_tables', 11,
  'global_default_acl_grants', 0,
  'public_default_acl_grants', 0
) AS hosted_grants_receipt;

ROLLBACK;
