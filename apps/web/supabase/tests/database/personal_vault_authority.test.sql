BEGIN;
SELECT plan(4);
SELECT ok(NOT has_function_privilege('anon', 'public.push_personal_vault(uuid,text,text,bigint)', 'EXECUTE'), 'anon cannot execute personal vault push');
SELECT ok(NOT has_function_privilege('authenticated', 'public.push_personal_vault(uuid,text,text,bigint)', 'EXECUTE'), 'authenticated cannot execute personal vault push');
SELECT ok(NOT has_table_privilege('authenticated', 'public.team_vault_blobs', 'SELECT'), 'authenticated cannot read team vault blobs');
SELECT ok(
  NOT EXISTS (
    SELECT 1
    FROM unnest(ARRAY['anon', 'authenticated']) AS roles(role_name)
    CROSS JOIN unnest(
      ARRAY['public.oauth_states', 'public.platform_tokens']
    ) AS target_tables(table_name)
    CROSS JOIN unnest(
      ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']
    ) AS requested_privileges(privilege_name)
    JOIN pg_catalog.pg_attribute AS attr
      ON attr.attrelid = target_tables.table_name::regclass
     AND attr.attnum > 0
     AND NOT attr.attisdropped
    WHERE has_column_privilege(
      roles.role_name,
      attr.attrelid,
      attr.attnum,
      requested_privileges.privilege_name
    )
  ),
  'anon and authenticated have no column privileges on platform_tokens or oauth_states'
);
SELECT * FROM finish();
ROLLBACK;
