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
