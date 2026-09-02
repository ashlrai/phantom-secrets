-- Resolve local Supabase security/performance advisor findings without
-- widening any row-level authority. Wrapping auth.uid() in a scalar SELECT
-- lets PostgreSQL compute the stable request identity once per statement.

BEGIN;

ALTER POLICY users_read_own ON public.users
  USING (id = (SELECT auth.uid()));

ALTER POLICY device_tokens_read_own ON public.device_tokens
  USING (user_id = (SELECT auth.uid()));

ALTER POLICY team_key_shares_own ON public.team_key_shares
  USING (user_id = (SELECT auth.uid()));

-- Both trigger functions use only row values and pg_catalog built-ins. Pinning
-- their resolution path prevents a caller-controlled schema from shadowing a
-- function or operator used by a future function-body change.
ALTER FUNCTION public.update_updated_at() SET search_path = pg_catalog;
ALTER FUNCTION public.prevent_user_billing_self_update()
  SET search_path = pg_catalog;

COMMIT;
