# Rollback SQL for the Supabase migrations in ../migrations

Not applied automatically. Run in reverse order of the up migrations:
1. `20261009231437_clamp_browser_table_authority.down.sql`
2. `20261009225441_enforce_personal_vault_quota.down.sql`

Before applying the clamp to a real database, generate that database's own
restore list with `gen_restore_grants.sql` and use it in the clamp rollback.
