\set ON_ERROR_STOP on

DO $$
DECLARE
  hardened_read_policies integer;
  pinned_trigger_functions integer;
BEGIN
  SELECT count(*)
  INTO hardened_read_policies
  FROM pg_policies
  WHERE schemaname = 'public'
    AND (tablename, policyname) IN (
      ('users', 'users_read_own'),
      ('device_tokens', 'device_tokens_read_own'),
      ('team_key_shares', 'team_key_shares_own')
    )
    AND cmd = 'SELECT'
    AND permissive = 'PERMISSIVE'
    AND roles = ARRAY['public']::name[];

  IF hardened_read_policies <> 3 THEN
    RAISE EXCEPTION 'expected three unchanged public SELECT policy boundaries';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_policies
    WHERE schemaname = 'public'
      AND tablename = 'users'
      AND policyname = 'users_update_own'
  ) THEN
    RAISE EXCEPTION 'users_update_own must remain absent';
  END IF;

  IF has_table_privilege('authenticated', 'public.users', 'UPDATE') THEN
    RAISE EXCEPTION 'authenticated must not have UPDATE on public.users';
  END IF;

  SELECT count(*)
  INTO pinned_trigger_functions
  FROM pg_proc AS proc
  JOIN pg_namespace AS namespace ON namespace.oid = proc.pronamespace
  WHERE namespace.nspname = 'public'
    AND proc.proname IN (
      'update_updated_at',
      'prevent_user_billing_self_update'
    )
    AND pg_get_function_identity_arguments(proc.oid) = ''
    AND NOT proc.prosecdef
    AND 'search_path=pg_catalog' = ANY(proc.proconfig);

  IF pinned_trigger_functions <> 2 THEN
    RAISE EXCEPTION 'expected two trigger functions with pinned search paths';
  END IF;
END
$$;

DO $$
DECLARE
  encrypted_token_columns integer;
  hardened_oauth_functions integer;
  protected_oauth_tables integer;
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'platform_tokens'
      AND column_name = 'access_token'
  ) THEN
    RAISE EXCEPTION 'platform_tokens must not retain a plaintext access_token column';
  END IF;

  SELECT count(*)
  INTO encrypted_token_columns
  FROM information_schema.columns
  WHERE table_schema = 'public'
    AND table_name = 'platform_tokens'
    AND column_name IN (
      'access_token_ciphertext',
      'access_token_nonce',
      'access_token_tag',
      'encryption_key_version'
    );

  IF encrypted_token_columns <> 4 THEN
    RAISE EXCEPTION 'platform_tokens encrypted envelope is incomplete';
  END IF;

  SELECT count(*)
  INTO protected_oauth_tables
  FROM pg_class AS relation
  JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
  WHERE namespace.nspname = 'public'
    AND relation.relname IN ('oauth_states', 'platform_tokens')
    AND relation.relrowsecurity;

  IF protected_oauth_tables <> 2 THEN
    RAISE EXCEPTION 'OAuth state and platform token tables must have RLS enabled';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_policies
    WHERE schemaname = 'public'
      AND tablename IN ('oauth_states', 'platform_tokens')
  ) THEN
    RAISE EXCEPTION 'OAuth state and platform token tables must not expose RLS policies';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM unnest(ARRAY['anon', 'authenticated']) AS roles(role_name)
    CROSS JOIN unnest(
      ARRAY['public.oauth_states', 'public.platform_tokens']
    ) AS target_tables(table_name)
    CROSS JOIN unnest(
      ARRAY[
        'SELECT',
        'INSERT',
        'UPDATE',
        'DELETE',
        'TRUNCATE',
        'REFERENCES',
        'TRIGGER'
      ]
    ) AS requested_privileges(privilege_name)
    WHERE has_table_privilege(
      roles.role_name,
      target_tables.table_name,
      requested_privileges.privilege_name
    )
  ) THEN
    RAISE EXCEPTION 'public clients must not access OAuth state or platform tokens';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM unnest(
      ARRAY['public.oauth_states', 'public.platform_tokens']
    ) AS target_tables(table_name)
    CROSS JOIN unnest(
      ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE']
    ) AS requested_privileges(privilege_name)
    WHERE NOT has_table_privilege(
      'service_role',
      target_tables.table_name,
      requested_privileges.privilege_name
    )
  ) THEN
    RAISE EXCEPTION 'service role OAuth table grants are incomplete';
  END IF;

  SELECT count(*)
  INTO hardened_oauth_functions
  FROM pg_proc AS proc
  JOIN pg_namespace AS namespace ON namespace.oid = proc.pronamespace
  WHERE namespace.nspname = 'public'
    AND proc.proname IN (
      'issue_vercel_oauth_state',
      'consume_vercel_oauth_state'
    )
    AND pg_get_function_identity_arguments(proc.oid) = 'p_state_hash bytea, p_user_id uuid'
    AND NOT proc.prosecdef
    AND 'search_path=pg_catalog' = ANY(proc.proconfig);

  IF hardened_oauth_functions <> 2 THEN
    RAISE EXCEPTION 'OAuth state functions must be invoker-safe with pinned paths';
  END IF;

  IF has_function_privilege(
    'anon',
    'public.consume_vercel_oauth_state(bytea, uuid)',
    'EXECUTE'
  ) OR has_function_privilege(
    'authenticated',
    'public.consume_vercel_oauth_state(bytea, uuid)',
    'EXECUTE'
  ) OR has_function_privilege(
    'anon',
    'public.issue_vercel_oauth_state(bytea, uuid)',
    'EXECUTE'
  ) OR has_function_privilege(
    'authenticated',
    'public.issue_vercel_oauth_state(bytea, uuid)',
    'EXECUTE'
  ) THEN
    RAISE EXCEPTION 'public clients must not execute OAuth state consumption';
  END IF;
END
$$;
