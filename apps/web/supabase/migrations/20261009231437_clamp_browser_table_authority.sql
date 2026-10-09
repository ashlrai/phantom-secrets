-- Browser access is read-only and bounded by the existing ownership/membership
-- RLS policies. REVOKE ALL also closes TRUNCATE/REFERENCES and other privileges
-- that row-level security cannot constrain. Do not change trusted service_role
-- grants, function authority, or global defaults for unrelated future tables.
REVOKE ALL PRIVILEGES ON TABLE
  public.users, public.vault_blobs, public.device_tokens,
  public.teams, public.team_members, public.team_vault_blobs,
  public.team_key_shares, public.platform_tokens, public.stripe_processed_events,
  public.stripe_subscription_users, public.device_auth_rate_limits
FROM PUBLIC, anon, authenticated;

GRANT SELECT ON TABLE
  public.users, public.vault_blobs, public.teams,
  public.team_members, public.team_vault_blobs
TO authenticated;
