-- Bind team invitations to server-managed provider identity and replace the
-- raceable database-wide device-code throttle with an atomic, per-client
-- limiter plus a high global circuit breaker.

BEGIN;

-- Public profile rows are derived from a verified Supabase Auth session by
-- service-role APIs. Authenticated Data API clients have no legitimate direct
-- update path, so remove the broad self-update capability entirely.
DROP POLICY IF EXISTS "users_update_own" ON public.users;
REVOKE UPDATE ON TABLE public.users FROM PUBLIC, anon, authenticated;

-- Existing public profile rows predate the verified-identity lookup used by the
-- application. Reconcile them from the Auth provider boundary before enforcing
-- uniqueness. These locks keep the identity snapshot stable while the repair
-- and index are installed.
LOCK TABLE auth.identities IN SHARE MODE;
LOCK TABLE public.users IN ACCESS EXCLUSIVE MODE;

CREATE TEMP TABLE phantom_verified_github_identities ON COMMIT DROP AS
SELECT
  profile.id AS user_id,
  identity.id AS identity_id,
  lower(
    btrim(
      COALESCE(
        NULLIF(btrim(identity.identity_data ->> 'user_name'), ''),
        NULLIF(btrim(identity.identity_data ->> 'preferred_username'), ''),
        NULLIF(btrim(identity.identity_data ->> 'login'), '')
      )
    )
  ) AS verified_login
FROM public.users AS profile
LEFT JOIN auth.identities AS identity
  ON identity.user_id = profile.id
 AND identity.provider = 'github';

DO $$
DECLARE
  invalid_user_count bigint;
  invalid_login_count bigint;
  colliding_login_count bigint;
BEGIN
  SELECT count(*)
  INTO invalid_user_count
  FROM (
    SELECT user_id
    FROM phantom_verified_github_identities
    GROUP BY user_id
    HAVING count(identity_id) <> 1
  ) AS invalid_users;

  IF invalid_user_count > 0 THEN
    RAISE EXCEPTION
      'GitHub identity reconciliation blocked: % public user(s) do not have exactly one GitHub provider identity',
      invalid_user_count;
  END IF;

  SELECT count(*)
  INTO invalid_login_count
  FROM phantom_verified_github_identities
  WHERE identity_id IS NOT NULL
    AND (
      verified_login IS NULL
      OR verified_login !~ '^[a-z0-9][a-z0-9-]{0,38}$'
      OR verified_login ~ '-$'
    );

  IF invalid_login_count > 0 THEN
    RAISE EXCEPTION
      'GitHub identity reconciliation blocked: % provider identity record(s) have no valid GitHub login',
      invalid_login_count;
  END IF;

  SELECT count(*)
  INTO colliding_login_count
  FROM (
    SELECT verified_login
    FROM phantom_verified_github_identities
    WHERE identity_id IS NOT NULL
    GROUP BY verified_login
    HAVING count(DISTINCT user_id) > 1
  ) AS colliding_logins;

  IF colliding_login_count > 0 THEN
    RAISE EXCEPTION
      'GitHub identity reconciliation blocked: % verified login collision(s) require operator review',
      colliding_login_count;
  END IF;
END;
$$;

-- Correct poisoned/stale logins by stable user id. No profile is deleted or
-- re-keyed, so vault, team, billing, and audit references remain intact. Keep
-- the prior profile timestamp because this is an identity repair, not a user
-- initiated business-data update.
ALTER TABLE public.users DISABLE TRIGGER users_updated_at;

UPDATE public.users AS profile
SET github_login = identity.verified_login
FROM phantom_verified_github_identities AS identity
WHERE identity.user_id = profile.id
  AND identity.identity_id IS NOT NULL
  AND profile.github_login IS DISTINCT FROM identity.verified_login;

ALTER TABLE public.users ENABLE TRIGGER users_updated_at;

ALTER TABLE public.users
  ADD COLUMN IF NOT EXISTS github_login_normalized text
  GENERATED ALWAYS AS (lower(btrim(github_login))) STORED;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM public.users
    GROUP BY github_login_normalized
    HAVING count(*) > 1
  ) THEN
    RAISE EXCEPTION 'duplicate normalized GitHub logins must be resolved before identity hardening';
  END IF;
END
$$;

CREATE UNIQUE INDEX IF NOT EXISTS users_github_login_normalized_unique
  ON public.users (github_login_normalized);

ALTER TABLE public.device_tokens
  ADD COLUMN IF NOT EXISTS issuance_key_hash text;

CREATE INDEX IF NOT EXISTS device_tokens_active_issuance_key
  ON public.device_tokens (issuance_key_hash, device_expires_at)
  WHERE status = 'pending' AND issuance_key_hash IS NOT NULL;

CREATE TABLE IF NOT EXISTS public.device_auth_rate_limits (
  key_hash text PRIMARY KEY,
  window_started_at timestamptz NOT NULL,
  request_count integer NOT NULL CHECK (request_count > 0),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT device_auth_rate_limits_key_hash_check
    CHECK (key_hash ~ '^[0-9a-f]{64}$')
);

ALTER TABLE public.device_auth_rate_limits ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.device_auth_rate_limits FROM PUBLIC, anon, authenticated;

CREATE INDEX IF NOT EXISTS device_auth_rate_limits_updated_at
  ON public.device_auth_rate_limits (updated_at);

CREATE OR REPLACE FUNCTION public.issue_device_code(
  p_client_key_hash text,
  p_device_code text,
  p_user_code text,
  p_expires_at timestamptz
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_now timestamptz := clock_timestamp();
  v_window timestamptz;
  v_global_count integer;
  v_client_count integer;
  v_pending_count integer;
  v_global_key constant text := repeat('0', 64);
BEGIN
  IF p_client_key_hash IS NULL OR p_client_key_hash !~ '^[0-9a-f]{64}$' OR
     p_device_code IS NULL OR p_device_code !~
       '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' OR
     p_user_code IS NULL OR p_user_code !~ '^[A-HJ-NP-Z2-9]{8}$' OR
     p_expires_at <= v_now OR p_expires_at > v_now + interval '16 minutes' THEN
    RAISE EXCEPTION 'invalid device-code issuance request';
  END IF;

  v_window := date_trunc('minute', v_now);

  -- Take the fixed global row first and the client row second on every call.
  -- The upserts serialize concurrent increments and avoid count/insert races.
  INSERT INTO public.device_auth_rate_limits (
    key_hash, window_started_at, request_count, updated_at
  ) VALUES (v_global_key, v_window, 1, v_now)
  ON CONFLICT (key_hash) DO UPDATE
  SET window_started_at = CASE
        WHEN public.device_auth_rate_limits.window_started_at = v_window
          THEN public.device_auth_rate_limits.window_started_at
        ELSE v_window
      END,
      request_count = CASE
        WHEN public.device_auth_rate_limits.window_started_at = v_window
          THEN public.device_auth_rate_limits.request_count + 1
        ELSE 1
      END,
      updated_at = v_now
  RETURNING request_count INTO v_global_count;

  INSERT INTO public.device_auth_rate_limits (
    key_hash, window_started_at, request_count, updated_at
  ) VALUES (p_client_key_hash, v_window, 1, v_now)
  ON CONFLICT (key_hash) DO UPDATE
  SET window_started_at = CASE
        WHEN public.device_auth_rate_limits.window_started_at = v_window
          THEN public.device_auth_rate_limits.window_started_at
        ELSE v_window
      END,
      request_count = CASE
        WHEN public.device_auth_rate_limits.window_started_at = v_window
          THEN public.device_auth_rate_limits.request_count + 1
        ELSE 1
      END,
      updated_at = v_now
  RETURNING request_count INTO v_client_count;

  IF v_global_count > 3000 THEN
    RETURN 'global_rate_limited';
  END IF;
  IF v_client_count > 12 THEN
    RETURN 'client_rate_limited';
  END IF;

  SELECT count(*) INTO v_pending_count
  FROM public.device_tokens
  WHERE issuance_key_hash = p_client_key_hash
    AND status = 'pending'
    AND device_expires_at > v_now;
  IF v_pending_count >= 5 THEN
    RETURN 'too_many_pending';
  END IF;

  INSERT INTO public.device_tokens (
    device_code, user_code, status, expires_at, device_expires_at,
    issuance_key_hash
  ) VALUES (
    p_device_code, p_user_code, 'pending', p_expires_at, p_expires_at,
    p_client_key_hash
  );

  -- Opportunistically bound stale limiter state without holding a long lock.
  DELETE FROM public.device_auth_rate_limits
  WHERE key_hash IN (
    SELECT key_hash
    FROM public.device_auth_rate_limits
    WHERE updated_at < v_now - interval '1 day'
    ORDER BY updated_at
    LIMIT 128
    FOR UPDATE SKIP LOCKED
  );

  RETURN 'issued';
END;
$$;

REVOKE ALL ON FUNCTION public.issue_device_code(text, text, text, timestamptz)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.issue_device_code(text, text, text, timestamptz)
  TO service_role;

COMMIT;
