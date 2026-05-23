-- Harden device auth expiry, user billing fields, and team vault writes.

-- Device-code expiry is short-lived, but issued CLI bearer tokens need their
-- own longer-lived expiry. Keep expires_at for backward compatibility with
-- existing rows and clients, and mirror it into device_expires_at.
ALTER TABLE public.device_tokens
  ADD COLUMN IF NOT EXISTS device_expires_at timestamptz,
  ADD COLUMN IF NOT EXISTS token_expires_at timestamptz,
  ADD COLUMN IF NOT EXISTS approved_at timestamptz,
  ADD COLUMN IF NOT EXISTS claimed_at timestamptz;

UPDATE public.device_tokens
SET device_expires_at = COALESCE(device_expires_at, expires_at)
WHERE device_expires_at IS NULL;

CREATE INDEX IF NOT EXISTS device_tokens_token_hash_token_expiry
  ON public.device_tokens(token_hash, token_expires_at)
  WHERE token_hash IS NOT NULL;

-- Authenticated users may edit profile-style fields in future, but never
-- billing/plan fields. Service-role API/webhook code is allowed through.
CREATE OR REPLACE FUNCTION public.prevent_user_billing_self_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF auth.role() = 'authenticated' AND (
    NEW.plan IS DISTINCT FROM OLD.plan OR
    NEW.plan_expires_at IS DISTINCT FROM OLD.plan_expires_at OR
    NEW.stripe_customer_id IS DISTINCT FROM OLD.stripe_customer_id OR
    NEW.subscription_id IS DISTINCT FROM OLD.subscription_id
  ) THEN
    RAISE EXCEPTION 'billing fields are managed by Phantom server APIs';
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS users_prevent_billing_self_update ON public.users;
CREATE TRIGGER users_prevent_billing_self_update
  BEFORE UPDATE ON public.users
  FOR EACH ROW EXECUTE FUNCTION public.prevent_user_billing_self_update();

-- Team vault writes must pass through the API so Pro gates, key-share checks,
-- blob limits, and compare-and-swap semantics cannot be bypassed directly via
-- the Supabase Data API. Members may still read vault metadata/rows permitted
-- by RLS; service-role API routes perform writes.
DROP POLICY IF EXISTS team_vault_blobs_member ON public.team_vault_blobs;
CREATE POLICY team_vault_blobs_member_read ON public.team_vault_blobs
  FOR SELECT
  USING (
    EXISTS (
      SELECT 1
      FROM public.team_members
      WHERE team_id = team_vault_blobs.team_id
        AND user_id = auth.uid()
    )
  );
