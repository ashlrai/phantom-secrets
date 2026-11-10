-- Emits GRANT statements that recreate the current PUBLIC/anon/authenticated grants
-- on the tables touched by 20261009231437. Run BEFORE applying; save output as the rollback body.
SELECT format('GRANT %s ON TABLE public.%I TO %s;', a.privilege_type, c.relname,
              CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE quote_ident(g.rolname) END)
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN LATERAL aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a
LEFT JOIN pg_roles g ON g.oid = a.grantee
WHERE n.nspname = 'public' AND c.relname IN ('users','vault_blobs','device_tokens','teams','team_members','team_vault_blobs','team_key_shares','platform_tokens','stripe_processed_events','stripe_subscription_users','device_auth_rate_limits')
  AND (a.grantee = 0 OR g.rolname IN ('anon','authenticated'))
ORDER BY c.relname, 1;
