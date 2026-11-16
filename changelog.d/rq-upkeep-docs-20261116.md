### Security (Personal Cloud token and OAuth-state grants)

- The Supabase migration `20261110053000_revoke_platform_token_oauth_state_columns`
  follows `20261009231437_clamp_browser_table_authority`, whose column revoke
  omitted `platform_tokens` and `oauth_states` and whose table-level revoke
  omitted `oauth_states`. Column grants survive a table-level `REVOKE`, so it
  revokes every `PUBLIC`, `anon` and `authenticated` privilege on `oauth_states`
  and the column privileges on both tables. `service_role` table privileges are
  kept. The migration fails if either table is missing. A rollback script and
  the local grant assertions in `scripts/supabase/assert-local-authority.sql`
  cover it.

### Fixed (`phantom-secrets-mcp` unsupported platform)

- The `phantom-secrets-mcp` npm wrapper resolves the release target before it
  touches the cache, lock, or network. An unsupported platform now exits with
  release guidance and leaves nothing behind, matching the `phantom-secrets`
  wrapper.
