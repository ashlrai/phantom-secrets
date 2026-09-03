BEGIN;

SELECT plan(44);

-- One shared matrix definition feeds both the cardinality guards and every
-- effective-privilege cell. Removing a role, table, or PostgreSQL 17 privilege
-- therefore fails a dedicated count before it can reduce the matrix silently.
CREATE TEMP TABLE expected_data_api_roles (
  role_name text PRIMARY KEY
) ON COMMIT DROP;
INSERT INTO expected_data_api_roles (role_name) VALUES
  ('anon'),
  ('authenticated'),
  ('service_role');

CREATE TEMP TABLE expected_data_api_tables (
  table_name text PRIMARY KEY,
  authenticated_privileges text[] NOT NULL,
  service_privileges text[] NOT NULL
) ON COMMIT DROP;
INSERT INTO expected_data_api_tables (
  table_name, authenticated_privileges, service_privileges
) VALUES
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
  ('device_auth_rate_limits', ARRAY[]::text[], ARRAY[]::text[]);

CREATE TEMP TABLE expected_table_privileges (
  privilege_name text PRIMARY KEY
) ON COMMIT DROP;
INSERT INTO expected_table_privileges (privilege_name) VALUES
  ('SELECT'),
  ('INSERT'),
  ('UPDATE'),
  ('DELETE'),
  ('TRUNCATE'),
  ('REFERENCES'),
  ('TRIGGER'),
  ('MAINTAIN');

CREATE TEMP TABLE expected_data_api_functions (
  function_name text PRIMARY KEY,
  authenticated_execute boolean NOT NULL,
  service_execute boolean NOT NULL
) ON COMMIT DROP;
INSERT INTO expected_data_api_functions (
  function_name, authenticated_execute, service_execute
) VALUES
  ('public.update_updated_at()', false, false),
  ('public.prevent_user_billing_self_update()', false, false),
  ('public.issue_device_code(text,text,text,timestamptz)', false, true),
  ('public.process_stripe_billing_event(text,text,bigint,uuid,uuid,text,text,timestamptz)', false, true),
  ('app_private.current_user_is_team_member(uuid)', true, false);

-- Fixed identities make failures reproducible and keep this transaction fully
-- disposable. The postgres test role seeds rows before switching to the same
-- anon/authenticated roles used by PostgREST.
INSERT INTO auth.users (id) VALUES
  ('10000000-0000-4000-8000-000000000001'),
  ('10000000-0000-4000-8000-000000000002'),
  ('10000000-0000-4000-8000-000000000003');

INSERT INTO public.users (id, github_login, email) VALUES
  ('10000000-0000-4000-8000-000000000001', 'phantom-test-a', 'a@example.invalid'),
  ('10000000-0000-4000-8000-000000000002', 'phantom-test-b', 'b@example.invalid'),
  ('10000000-0000-4000-8000-000000000003', 'phantom-test-c', 'c@example.invalid');

INSERT INTO public.vault_blobs (
  user_id, project_id, encrypted_blob
) VALUES
  ('10000000-0000-4000-8000-000000000001', 'owner-a', 'ciphertext-a'),
  ('10000000-0000-4000-8000-000000000002', 'owner-b', 'ciphertext-b');

INSERT INTO public.teams (id, name, owner_id) VALUES
  ('20000000-0000-4000-8000-000000000001', 'Team A', '10000000-0000-4000-8000-000000000001'),
  ('20000000-0000-4000-8000-000000000002', 'Team B', '10000000-0000-4000-8000-000000000003');

INSERT INTO public.team_members (team_id, user_id, role) VALUES
  ('20000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000001', 'owner'),
  ('20000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000002', 'member'),
  ('20000000-0000-4000-8000-000000000002', '10000000-0000-4000-8000-000000000003', 'owner');

SELECT ok(
  NOT has_table_privilege('anon', 'public.users', 'SELECT')
    AND NOT has_table_privilege('anon', 'public.users', 'INSERT')
    AND NOT has_table_privilege('anon', 'public.users', 'UPDATE')
    AND NOT has_table_privilege('anon', 'public.users', 'DELETE'),
  'anon has no user-table access'
);
SELECT ok(
  NOT has_table_privilege('anon', 'public.vault_blobs', 'SELECT')
    AND NOT has_table_privilege('anon', 'public.vault_blobs', 'INSERT')
    AND NOT has_table_privilege('anon', 'public.vault_blobs', 'UPDATE')
    AND NOT has_table_privilege('anon', 'public.vault_blobs', 'DELETE'),
  'anon has no personal-vault access'
);
SELECT ok(
  NOT has_table_privilege('anon', 'public.teams', 'SELECT')
    AND NOT has_table_privilege('anon', 'public.teams', 'INSERT')
    AND NOT has_table_privilege('anon', 'public.teams', 'UPDATE')
    AND NOT has_table_privilege('anon', 'public.teams', 'DELETE'),
  'anon has no team access'
);
SELECT ok(
  NOT has_table_privilege('anon', 'public.team_members', 'SELECT')
    AND NOT has_table_privilege('anon', 'public.team_members', 'INSERT')
    AND NOT has_table_privilege('anon', 'public.team_members', 'UPDATE')
    AND NOT has_table_privilege('anon', 'public.team_members', 'DELETE'),
  'anon has no team-membership access'
);

SELECT ok(
  has_table_privilege('authenticated', 'public.users', 'SELECT')
    AND NOT has_table_privilege('authenticated', 'public.users', 'INSERT')
    AND NOT has_table_privilege('authenticated', 'public.users', 'UPDATE')
    AND NOT has_table_privilege('authenticated', 'public.users', 'DELETE'),
  'authenticated can only select users'
);
SELECT ok(
  has_table_privilege('authenticated', 'public.vault_blobs', 'SELECT')
    AND NOT has_table_privilege('authenticated', 'public.vault_blobs', 'INSERT')
    AND NOT has_table_privilege('authenticated', 'public.vault_blobs', 'UPDATE')
    AND NOT has_table_privilege('authenticated', 'public.vault_blobs', 'DELETE'),
  'authenticated can only select personal vaults'
);
SELECT ok(
  has_table_privilege('authenticated', 'public.teams', 'SELECT')
    AND NOT has_table_privilege('authenticated', 'public.teams', 'INSERT')
    AND NOT has_table_privilege('authenticated', 'public.teams', 'UPDATE')
    AND NOT has_table_privilege('authenticated', 'public.teams', 'DELETE'),
  'authenticated can only select teams'
);
SELECT ok(
  has_table_privilege('authenticated', 'public.team_members', 'SELECT')
    AND NOT has_table_privilege('authenticated', 'public.team_members', 'INSERT')
    AND NOT has_table_privilege('authenticated', 'public.team_members', 'UPDATE')
    AND NOT has_table_privilege('authenticated', 'public.team_members', 'DELETE'),
  'authenticated can only select team memberships'
);
SELECT ok(
  NOT has_table_privilege('authenticated', 'public.device_tokens', 'SELECT')
    AND NOT has_table_privilege('authenticated', 'public.device_tokens', 'INSERT')
    AND NOT has_table_privilege('authenticated', 'public.device_tokens', 'UPDATE')
    AND NOT has_table_privilege('authenticated', 'public.device_tokens', 'DELETE'),
  'authenticated cannot access device tokens directly'
);
SELECT ok(
  NOT has_table_privilege('authenticated', 'public.team_vault_blobs', 'SELECT')
    AND NOT has_table_privilege('authenticated', 'public.team_vault_blobs', 'INSERT')
    AND NOT has_table_privilege('authenticated', 'public.team_vault_blobs', 'UPDATE')
    AND NOT has_table_privilege('authenticated', 'public.team_vault_blobs', 'DELETE'),
  'authenticated cannot access team ciphertext directly'
);
SELECT ok(
  NOT has_table_privilege('authenticated', 'public.team_key_shares', 'SELECT')
    AND NOT has_table_privilege('authenticated', 'public.team_key_shares', 'INSERT')
    AND NOT has_table_privilege('authenticated', 'public.team_key_shares', 'UPDATE')
    AND NOT has_table_privilege('authenticated', 'public.team_key_shares', 'DELETE'),
  'authenticated cannot access legacy team key shares directly'
);
SELECT ok(
  NOT has_table_privilege('authenticated', 'public.platform_tokens', 'SELECT')
    AND NOT has_table_privilege('authenticated', 'public.platform_tokens', 'INSERT')
    AND NOT has_table_privilege('authenticated', 'public.platform_tokens', 'UPDATE')
    AND NOT has_table_privilege('authenticated', 'public.platform_tokens', 'DELETE'),
  'authenticated cannot access platform credentials'
);
SELECT is(
  (
    SELECT count(*)
    FROM pg_catalog.pg_class AS relation
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
      AND relation.relrowsecurity
  ),
  11::bigint,
  'RLS remains enabled on every Phantom Data API table'
);
SELECT is(
  (
    WITH object_types(object_type) AS (
      VALUES ('r'::"char"), ('S'::"char"), ('f'::"char")
    ),
    global_defaults(acl) AS (
      SELECT coalesce(
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
    ),
    forbidden_defaults AS (
      SELECT privilege.grantee
      FROM global_defaults
      CROSS JOIN LATERAL pg_catalog.aclexplode(global_defaults.acl) AS privilege
      WHERE privilege.grantee = 0
        OR pg_catalog.pg_get_userbyid(privilege.grantee) = ANY (
          ARRAY['anon', 'authenticated', 'service_role']
        )
      UNION ALL
      SELECT privilege.grantee
      FROM pg_catalog.pg_default_acl AS defaults
      JOIN pg_catalog.pg_namespace AS namespace
        ON namespace.oid = defaults.defaclnamespace
      CROSS JOIN LATERAL pg_catalog.aclexplode(defaults.defaclacl) AS privilege
      WHERE namespace.nspname = 'public'
        AND (
          privilege.grantee = 0
          OR pg_catalog.pg_get_userbyid(privilege.grantee) = ANY (
            ARRAY['anon', 'authenticated', 'service_role']
          )
        )
    )
    SELECT count(*) FROM forbidden_defaults
  ),
  0::bigint,
  'global and public-schema defaults grant no future Data API privilege'
);

CREATE FUNCTION public.phantom_default_acl_probe()
RETURNS void
LANGUAGE sql
SET search_path = pg_catalog
AS 'SELECT';

SELECT ok(
  NOT has_function_privilege(
    'anon', 'public.phantom_default_acl_probe()', 'EXECUTE'
  ) AND NOT has_function_privilege(
    'authenticated', 'public.phantom_default_acl_probe()', 'EXECUTE'
  ) AND NOT has_function_privilege(
    'service_role', 'public.phantom_default_acl_probe()', 'EXECUTE'
  ),
  'a newly created postgres function does not inherit global PUBLIC EXECUTE'
);
SELECT is(
  (SELECT count(*) FROM expected_data_api_roles),
  3::bigint,
  'effective privilege matrix covers exactly three Data API roles'
);
SELECT is(
  (SELECT count(*) FROM expected_data_api_tables),
  11::bigint,
  'effective privilege matrix covers exactly eleven Phantom tables'
);
SELECT is(
  (SELECT count(*) FROM expected_table_privileges),
  8::bigint,
  'effective privilege matrix covers all eight PostgreSQL 17 table privileges'
);
SELECT is(
  (SELECT count(*) FROM expected_data_api_functions),
  5::bigint,
  'effective function matrix covers exactly five reviewed functions'
);
SELECT is(
  (
    SELECT count(*)
    FROM expected_data_api_roles AS roles
    CROSS JOIN expected_data_api_tables AS tables
    CROSS JOIN expected_table_privileges AS privileges
    WHERE has_table_privilege(
      roles.role_name,
      'public.' || tables.table_name,
      privileges.privilege_name
    ) IS DISTINCT FROM (
      CASE roles.role_name
        WHEN 'authenticated' THEN
          privileges.privilege_name = ANY (tables.authenticated_privileges)
        WHEN 'service_role' THEN
          privileges.privilege_name = ANY (tables.service_privileges)
        ELSE false
      END
    )
  ),
  0::bigint,
  'all 264 effective table privileges exactly match the reviewed role matrix'
);
SELECT is(
  (
    SELECT count(*)
    FROM expected_data_api_roles AS roles
    CROSS JOIN expected_data_api_functions AS functions
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
  0::bigint,
  'all 15 effective function privileges match the reviewed role matrix'
);
SELECT is(
  (
    SELECT count(*)
    FROM (
      SELECT 1
      FROM expected_data_api_roles AS roles
      CROSS JOIN expected_data_api_tables AS tables
      CROSS JOIN expected_table_privileges AS privileges
      WHERE has_table_privilege(
        roles.role_name,
        'public.' || tables.table_name,
        privileges.privilege_name || ' WITH GRANT OPTION'
      )
      UNION ALL
      SELECT 1
      FROM expected_data_api_roles AS roles
      CROSS JOIN expected_data_api_functions AS functions
      WHERE has_function_privilege(
        roles.role_name,
        functions.function_name,
        'EXECUTE WITH GRANT OPTION'
      )
    ) AS grant_options
  ),
  0::bigint,
  'Data API table and function privileges include no grant option'
);
SELECT ok(
  has_schema_privilege('authenticated', 'public', 'USAGE')
    AND has_schema_privilege('service_role', 'public', 'USAGE')
    AND has_schema_privilege('authenticated', 'app_private', 'USAGE')
    AND NOT has_schema_privilege('anon', 'app_private', 'USAGE')
    AND NOT has_schema_privilege('service_role', 'app_private', 'USAGE'),
  'schema usage is exactly sufficient for browser reads and the RLS helper'
);

SELECT ok(
  has_table_privilege('service_role', 'public.users', 'SELECT')
    AND has_table_privilege('service_role', 'public.users', 'INSERT')
    AND has_table_privilege('service_role', 'public.users', 'UPDATE')
    AND NOT has_table_privilege('service_role', 'public.users', 'DELETE'),
  'service_role has only required user operations'
);
SELECT ok(
  has_table_privilege('service_role', 'public.device_tokens', 'SELECT')
    AND has_table_privilege('service_role', 'public.device_tokens', 'UPDATE')
    AND NOT has_table_privilege('service_role', 'public.device_tokens', 'INSERT')
    AND NOT has_table_privilege('service_role', 'public.device_tokens', 'DELETE'),
  'service_role has only required device-token operations'
);
SELECT ok(
  has_table_privilege('service_role', 'public.vault_blobs', 'SELECT')
    AND has_table_privilege('service_role', 'public.vault_blobs', 'INSERT')
    AND has_table_privilege('service_role', 'public.vault_blobs', 'UPDATE')
    AND NOT has_table_privilege('service_role', 'public.vault_blobs', 'DELETE'),
  'service_role has only required personal-vault operations'
);
SELECT ok(
  has_table_privilege('service_role', 'public.teams', 'SELECT')
    AND has_table_privilege('service_role', 'public.teams', 'INSERT')
    AND has_table_privilege('service_role', 'public.teams', 'DELETE')
    AND NOT has_table_privilege('service_role', 'public.teams', 'UPDATE'),
  'service_role has only required team operations'
);
SELECT ok(
  has_table_privilege('service_role', 'public.team_members', 'SELECT')
    AND has_table_privilege('service_role', 'public.team_members', 'INSERT')
    AND has_table_privilege('service_role', 'public.team_members', 'UPDATE')
    AND has_table_privilege('service_role', 'public.team_members', 'DELETE'),
  'service_role has required team-membership operations'
);
SELECT ok(
  has_table_privilege('service_role', 'public.team_vault_blobs', 'SELECT')
    AND has_table_privilege('service_role', 'public.team_vault_blobs', 'INSERT')
    AND has_table_privilege('service_role', 'public.team_vault_blobs', 'UPDATE')
    AND NOT has_table_privilege('service_role', 'public.team_vault_blobs', 'DELETE'),
  'service_role has only required team-vault operations'
);
SELECT ok(
  NOT has_table_privilege('service_role', 'public.platform_tokens', 'SELECT')
    AND NOT has_table_privilege('service_role', 'public.platform_tokens', 'INSERT')
    AND NOT has_table_privilege('service_role', 'public.platform_tokens', 'UPDATE')
    AND NOT has_table_privilege('service_role', 'public.platform_tokens', 'DELETE'),
  'disabled platform integration has no service-role table path'
);
SELECT ok(
  NOT has_table_privilege('service_role', 'public.stripe_processed_events', 'SELECT')
    AND NOT has_table_privilege('service_role', 'public.stripe_processed_events', 'INSERT')
    AND NOT has_table_privilege('service_role', 'public.stripe_processed_events', 'UPDATE')
    AND NOT has_table_privilege('service_role', 'public.stripe_processed_events', 'DELETE')
    AND NOT has_table_privilege('service_role', 'public.stripe_subscription_users', 'SELECT')
    AND NOT has_table_privilege('service_role', 'public.stripe_subscription_users', 'INSERT')
    AND NOT has_table_privilege('service_role', 'public.stripe_subscription_users', 'UPDATE')
    AND NOT has_table_privilege('service_role', 'public.stripe_subscription_users', 'DELETE'),
  'billing internals are reachable only through the billing RPC'
);
SELECT ok(
  has_function_privilege(
    'service_role',
    'public.issue_device_code(text,text,text,timestamptz)',
    'EXECUTE'
  ),
  'service_role can execute device-code issuance'
);
SELECT ok(
  has_function_privilege(
    'service_role',
    'public.process_stripe_billing_event(text,text,bigint,uuid,uuid,text,text,timestamptz)',
    'EXECUTE'
  ),
  'service_role can execute transactional billing processing'
);
SELECT ok(
  NOT has_function_privilege(
    'authenticated',
    'public.issue_device_code(text,text,text,timestamptz)',
    'EXECUTE'
  ) AND NOT has_function_privilege(
    'anon',
    'public.issue_device_code(text,text,text,timestamptz)',
    'EXECUTE'
  ),
  'client roles cannot execute device-code issuance'
);
SELECT ok(
  NOT has_function_privilege(
    'authenticated',
    'public.process_stripe_billing_event(text,text,bigint,uuid,uuid,text,text,timestamptz)',
    'EXECUTE'
  ) AND NOT has_function_privilege(
    'anon',
    'public.process_stripe_billing_event(text,text,bigint,uuid,uuid,text,text,timestamptz)',
    'EXECUTE'
  ),
  'client roles cannot execute billing processing'
);
SELECT ok(
  NOT has_function_privilege(
    'authenticated',
    'public.update_updated_at()',
    'EXECUTE'
  ) AND NOT has_function_privilege(
    'authenticated',
    'public.prevent_user_billing_self_update()',
    'EXECUTE'
  ) AND NOT has_function_privilege(
    'service_role',
    'public.update_updated_at()',
    'EXECUTE'
  ) AND NOT has_function_privilege(
    'service_role',
    'public.prevent_user_billing_self_update()',
    'EXECUTE'
  ),
  'trigger helpers are not callable Data API RPCs'
);

SET LOCAL ROLE authenticated;
SET LOCAL request.jwt.claim.sub = '10000000-0000-4000-8000-000000000001';

SELECT results_eq(
  $$SELECT github_login FROM public.users ORDER BY github_login$$,
  ARRAY['phantom-test-a'::text],
  'user A reads only their profile'
);
SELECT results_eq(
  $$SELECT project_id FROM public.vault_blobs ORDER BY project_id$$,
  ARRAY['owner-a'::text],
  'user A reads only their personal vault metadata'
);
SELECT results_eq(
  $$SELECT name FROM public.teams ORDER BY name$$,
  ARRAY['Team A'::text],
  'user A reads only a team they belong to'
);
SELECT results_eq(
  $$SELECT user_id FROM public.team_members ORDER BY user_id$$,
  ARRAY[
    '10000000-0000-4000-8000-000000000001'::uuid,
    '10000000-0000-4000-8000-000000000002'::uuid
  ],
  'user A reads members of their team only'
);
SELECT is_empty(
  $$SELECT id FROM public.teams WHERE id = '20000000-0000-4000-8000-000000000002'$$,
  'user A cannot read another team'
);
SELECT is_empty(
  $$SELECT id FROM public.team_members WHERE team_id = '20000000-0000-4000-8000-000000000002'$$,
  'user A cannot read another team membership'
);
SELECT is_empty(
  $$SELECT id FROM public.vault_blobs WHERE user_id = '10000000-0000-4000-8000-000000000002'$$,
  'user A cannot read another personal vault'
);
SELECT throws_ok(
  $$UPDATE public.users SET email = 'blocked@example.invalid' WHERE id = '10000000-0000-4000-8000-000000000001'$$,
  '42501',
  NULL,
  'authenticated browser cannot write its own profile'
);

SELECT * FROM finish();
ROLLBACK;
