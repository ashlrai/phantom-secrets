-- Rollback for 20261009225441_enforce_personal_vault_quota.sql.
-- No earlier migration defines public.push_personal_vault, so the rollback
-- removes it. Warning: apps/web/src/app/api/v1/vault/push/route.ts calls this
-- function through rpc, so personal vault push fails while it is absent.
-- If the target database already had a version before the up migration, save
-- it first with:
--   SELECT pg_get_functiondef('public.push_personal_vault(uuid,text,text,bigint)'::regprocedure);
-- and restore that definition instead of dropping.
BEGIN;
DROP FUNCTION IF EXISTS public.push_personal_vault(uuid, text, text, bigint);
COMMIT;
