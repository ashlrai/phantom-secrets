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

  IF NOT EXISTS (
    SELECT 1
    FROM pg_class AS relation
    JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'public'
      AND relation.relname = 'oauth_states'
      AND relation.relrowsecurity
  ) THEN
    RAISE EXCEPTION 'oauth_states must have RLS enabled';
  END IF;

  IF has_table_privilege('anon', 'public.oauth_states', 'SELECT')
    OR has_table_privilege('authenticated', 'public.oauth_states', 'SELECT')
    OR has_table_privilege('anon', 'public.platform_tokens', 'SELECT')
    OR has_table_privilege('authenticated', 'public.platform_tokens', 'SELECT')
  THEN
    RAISE EXCEPTION 'public clients must not read OAuth state or platform tokens';
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
