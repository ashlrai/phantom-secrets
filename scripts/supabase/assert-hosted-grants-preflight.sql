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
  expected_functions constant text[] := ARRAY[
    'public.update_updated_at()',
    'public.prevent_user_billing_self_update()',
    'public.issue_device_code(text,text,text,timestamptz)',
    'public.process_stripe_billing_event(text,text,bigint,uuid,uuid,text,text,timestamptz)',
    'app_private.current_user_is_team_member(uuid)'
  ];
  found_tables integer;
  foreign_owned_tables integer;
  rls_tables integer;
  found_functions integer;
  foreign_owned_functions integer;
  public_schema_owner name;
  app_private_schema_owner name;
  found_columns integer;
  column_acl_cells integer;
  column_acl_mismatches integer;
BEGIN
  IF current_user <> 'postgres' THEN
    RAISE EXCEPTION
      'hosted grant preflight requires current_user postgres; found %',
      current_user;
  END IF;

  IF (
    SELECT count(*)
    FROM pg_catalog.pg_roles
    WHERE rolname = ANY (ARRAY['anon', 'authenticated', 'service_role'])
  ) <> 3 THEN
    RAISE EXCEPTION 'anon, authenticated, and service_role must all exist';
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

  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_roles
    WHERE rolname = ANY (ARRAY['anon', 'authenticated', 'service_role'])
      AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication)
  ) THEN
    RAISE EXCEPTION
      'Data API roles must not have superuser or cluster-management authority';
  END IF;

  -- A grant inherited from another role would survive direct revokes. Reject
  -- any effective inherited membership instead of assuming direct ACLs are the
  -- whole client authority surface.
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_roles AS client_role
    CROSS JOIN pg_catalog.pg_roles AS inherited_role
    WHERE client_role.rolname = ANY (
      ARRAY['anon', 'authenticated', 'service_role']
    )
      AND inherited_role.oid <> client_role.oid
      AND pg_catalog.pg_has_role(
        client_role.oid,
        inherited_role.oid,
        'USAGE'
      )
  ) THEN
    RAISE EXCEPTION
      'a Data API role has an effective inherited role membership';
  END IF;

  IF pg_catalog.pg_has_role('anon', 'service_role', 'MEMBER')
    OR pg_catalog.pg_has_role('authenticated', 'service_role', 'MEMBER')
    OR pg_catalog.pg_has_role('anon', 'postgres', 'MEMBER')
    OR pg_catalog.pg_has_role('authenticated', 'postgres', 'MEMBER') THEN
    RAISE EXCEPTION
      'a browser client role can assume a privileged server or migration role';
  END IF;

  SELECT owner.rolname
  INTO public_schema_owner
  FROM pg_catalog.pg_namespace AS namespace
  JOIN pg_catalog.pg_roles AS owner
    ON owner.oid = namespace.nspowner
  WHERE namespace.nspname = 'public';

  IF public_schema_owner IS NULL THEN
    RAISE EXCEPTION 'public schema must exist';
  END IF;

  IF public_schema_owner <> ALL (ARRAY['postgres', 'pg_database_owner']) THEN
    RAISE EXCEPTION
      'public schema has unreviewed owner %',
      public_schema_owner;
  END IF;

  -- Hosted Supabase intentionally makes postgres a non-superuser. Object
  -- ownership below supplies table/function/default-ACL authority; schema
  -- ownership (including implicit pg_database_owner membership) supplies the
  -- remaining schema grant authority.
  IF NOT (
    public_schema_owner = current_user
    OR pg_catalog.pg_has_role(current_user, public_schema_owner, 'USAGE')
  ) THEN
    RAISE EXCEPTION
      'postgres lacks authority over public schema owned by %',
      public_schema_owner;
  END IF;

  SELECT owner.rolname
  INTO app_private_schema_owner
  FROM pg_catalog.pg_namespace AS namespace
  JOIN pg_catalog.pg_roles AS owner
    ON owner.oid = namespace.nspowner
  WHERE namespace.nspname = 'app_private';

  IF app_private_schema_owner IS DISTINCT FROM 'postgres' THEN
    RAISE EXCEPTION
      'app_private schema must be owned by postgres; found %',
      coalesce(app_private_schema_owner, '<missing>');
  END IF;

  IF pg_catalog.has_schema_privilege('anon', 'public', 'CREATE')
    OR pg_catalog.has_schema_privilege('authenticated', 'public', 'CREATE')
    OR pg_catalog.has_schema_privilege('service_role', 'public', 'CREATE') THEN
    RAISE EXCEPTION
      'Data API roles must not create objects in the public schema';
  END IF;

  IF pg_catalog.has_schema_privilege('anon', 'app_private', 'CREATE')
    OR pg_catalog.has_schema_privilege(
      'authenticated', 'app_private', 'CREATE'
    )
    OR pg_catalog.has_schema_privilege(
      'service_role', 'app_private', 'CREATE'
    ) THEN
    RAISE EXCEPTION
      'Data API roles must not create objects in the app_private schema';
  END IF;

  IF NOT pg_catalog.has_schema_privilege(
    'authenticated', 'public', 'USAGE'
  ) OR NOT pg_catalog.has_schema_privilege(
    'service_role', 'public', 'USAGE'
  ) OR NOT pg_catalog.has_schema_privilege(
    'authenticated', 'app_private', 'USAGE'
  ) THEN
    RAISE EXCEPTION
      'required Data API schema usage is missing';
  END IF;

  IF pg_catalog.has_schema_privilege(
    'anon', 'app_private', 'USAGE'
  ) OR pg_catalog.has_schema_privilege(
    'service_role', 'app_private', 'USAGE'
  ) THEN
    RAISE EXCEPTION
      'app_private schema usage is broader than the authenticated RLS helper requires';
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
      'Data API schema privileges must not include WITH GRANT OPTION';
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

  WITH roles(role_name) AS (
    SELECT unnest(ARRAY['anon', 'authenticated', 'service_role'])
  ),
  privileges(privilege_name) AS (
    SELECT unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES'])
  ),
  columns(table_oid, table_name, column_name, column_acl) AS (
    SELECT
      relation.oid,
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
    count(*),
    count(*) FILTER (WHERE has_column_acl)
  INTO column_acl_cells, column_acl_mismatches
  FROM matrix;

  found_columns := column_acl_cells / 12;
  IF found_columns <> 84
    OR column_acl_cells <> 1008
    OR column_acl_mismatches <> 0 THEN
    RAISE EXCEPTION
      'column ACL preflight failed: columns %, cells %, grants %',
      found_columns,
      column_acl_cells,
      column_acl_mismatches;
  END IF;

  SELECT
    count(*),
    count(*) FILTER (WHERE owner.rolname <> 'postgres')
  INTO found_functions, foreign_owned_functions
  FROM pg_catalog.pg_proc AS function
  JOIN pg_catalog.pg_roles AS owner
    ON owner.oid = function.proowner
  WHERE function.oid = ANY (
    SELECT signature::regprocedure
    FROM unnest(expected_functions) AS signature
  );

  IF found_functions <> cardinality(expected_functions)
    OR foreign_owned_functions <> 0 THEN
    RAISE EXCEPTION
      'expected % postgres-owned Phantom functions; found %, with % foreign-owned',
      cardinality(expected_functions),
      found_functions,
      foreign_owned_functions;
  END IF;

  -- PostgreSQL's implicit global defaults are not stored in pg_default_acl
  -- until altered. Model those defaults explicitly and allow only the built-in,
  -- non-grantable PUBLIC EXECUTE that this migration intentionally removes.
  IF EXISTS (
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
    SELECT 1
    FROM global_defaults
    CROSS JOIN LATERAL pg_catalog.aclexplode(global_defaults.acl) AS privilege
    WHERE (
      privilege.grantee = 0
      OR pg_catalog.pg_get_userbyid(privilege.grantee) = ANY (
        ARRAY['anon', 'authenticated', 'service_role']
      )
    )
      AND NOT (
        privilege.grantee = 0
        AND global_defaults.object_type = 'f'::"char"
        AND privilege.privilege_type = 'EXECUTE'
        AND NOT privilege.is_grantable
      )
  ) THEN
    RAISE EXCEPTION
      'postgres has an unreviewed global default Data API grant';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_default_acl AS defaults
    CROSS JOIN LATERAL pg_catalog.aclexplode(defaults.defaclacl) AS privilege
    WHERE defaults.defaclnamespace = 0
      AND defaults.defaclrole <> 'postgres'::regrole
      AND (
        privilege.grantee = 0
        OR pg_catalog.pg_get_userbyid(privilege.grantee) = ANY (
          ARRAY['anon', 'authenticated', 'service_role']
        )
      )
  ) THEN
    RAISE EXCEPTION
      'a non-postgres owner has a global default Data API grant';
  END IF;

  -- The migration also resets public-schema defaults for objects later created
  -- by postgres. Fail if another creator has a schema-specific grant that would
  -- reopen Data API access outside that controlled default ACL.
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
