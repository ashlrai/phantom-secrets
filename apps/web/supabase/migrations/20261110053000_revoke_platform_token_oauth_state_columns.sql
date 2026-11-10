-- Follow-up to 20261009231437_clamp_browser_table_authority.sql.
-- That migration's column revoke omitted platform_tokens and oauth_states,
-- and its table-level REVOKE omitted oauth_states. Column grants survive a
-- table-level REVOKE, so both tables need an explicit column revoke.
-- Do not revoke service_role table privileges on these tables.
REVOKE ALL PRIVILEGES ON TABLE public.oauth_states
  FROM PUBLIC, anon, authenticated;

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
      AND c.relname = ANY (ARRAY['platform_tokens', 'oauth_states'])
      AND a.attnum > 0 AND NOT a.attisdropped
    GROUP BY n.nspname, c.relname
  LOOP
    FOREACH privilege_name IN ARRAY ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']
    LOOP
      EXECUTE format('REVOKE %s (%s) ON TABLE %s FROM PUBLIC, anon, authenticated, service_role',
        privilege_name, target.columns, target.table_name);
    END LOOP;
  END LOOP;

  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relkind IN ('r', 'p')
      AND c.relname = 'platform_tokens'
  ) OR NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relkind IN ('r', 'p')
      AND c.relname = 'oauth_states'
  ) THEN
    RAISE EXCEPTION 'platform_tokens and oauth_states must both exist for the column revoke';
  END IF;
END $$;
