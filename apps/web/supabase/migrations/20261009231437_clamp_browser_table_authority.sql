-- Browser access is read-only and bounded by the existing ownership/membership
-- RLS policies. REVOKE ALL also closes TRUNCATE/REFERENCES and other privileges
-- that row-level security cannot constrain. Close unnecessary service-role access and inherited column privileges.
REVOKE ALL PRIVILEGES ON TABLE
  public.users, public.vault_blobs, public.device_tokens,
  public.teams, public.team_members, public.team_vault_blobs,
  public.team_key_shares, public.platform_tokens, public.stripe_processed_events,
  public.stripe_subscription_users, public.device_auth_rate_limits
FROM PUBLIC, anon, authenticated;

GRANT SELECT ON TABLE
  public.users, public.vault_blobs, public.teams,
  public.team_members
TO authenticated;

REVOKE ALL PRIVILEGES ON TABLE
  public.team_key_shares, public.stripe_processed_events,
  public.stripe_subscription_users, public.device_auth_rate_limits
FROM service_role;

-- Remove column-level grants, which table-level REVOKE does not remove.
DO $$
DECLARE target record; privilege_name text;
BEGIN
  FOR target IN
    SELECT format('%I.%I', n.nspname, c.relname) AS table_name,
      string_agg(format('%I', a.attname), ', ' ORDER BY a.attnum) AS columns
    FROM pg_catalog.pg_attribute a
    JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
      AND c.relname = ANY (ARRAY['users', 'vault_blobs', 'device_tokens',
        'teams', 'team_members', 'team_vault_blobs', 'team_key_shares',
        'stripe_processed_events', 'stripe_subscription_users', 'device_auth_rate_limits'])
      AND a.attnum > 0 AND NOT a.attisdropped
    GROUP BY n.nspname, c.relname
  LOOP
    FOREACH privilege_name IN ARRAY ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']
    LOOP
      EXECUTE format('REVOKE %s (%s) ON TABLE %s FROM PUBLIC, anon, authenticated, service_role',
        privilege_name, target.columns, target.table_name);
    END LOOP;
  END LOOP;
END $$;

ALTER DEFAULT PRIVILEGES FOR ROLE postgres REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  REVOKE ALL ON TABLES FROM PUBLIC, anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  REVOKE ALL ON SEQUENCES FROM PUBLIC, anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  REVOKE ALL ON FUNCTIONS FROM PUBLIC, anon, authenticated, service_role;
