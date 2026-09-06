-- Dormant storage and one-time state primitives for a future Vercel OAuth
-- integration. The HTTP routes remain disabled; this migration does not
-- commission the integration or contact Vercel.

BEGIN;

-- There has never been a commissioned writer for platform_tokens. Refuse to
-- discard or reinterpret any unexpected legacy row, because its access_token
-- would be plaintext and requires an operator-led incident/migration decision.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM public.platform_tokens) THEN
    RAISE EXCEPTION
      'platform_tokens contains legacy rows; resolve them before applying encrypted OAuth storage';
  END IF;
END
$$;

ALTER TABLE public.platform_tokens
  DROP COLUMN access_token,
  ALTER COLUMN user_id TYPE uuid USING user_id::uuid,
  ADD COLUMN platform_account_id text NOT NULL,
  ADD COLUMN access_token_ciphertext bytea NOT NULL,
  ADD COLUMN access_token_nonce bytea NOT NULL,
  ADD COLUMN access_token_tag bytea NOT NULL,
  ADD COLUMN encryption_key_version integer NOT NULL;

ALTER TABLE public.platform_tokens
  ADD CONSTRAINT platform_tokens_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE,
  ADD CONSTRAINT platform_tokens_platform_account_id_length
    CHECK (char_length(platform_account_id) BETWEEN 1 AND 256),
  ADD CONSTRAINT platform_tokens_ciphertext_length
    CHECK (octet_length(access_token_ciphertext) BETWEEN 1 AND 65536),
  ADD CONSTRAINT platform_tokens_nonce_length
    CHECK (octet_length(access_token_nonce) = 12),
  ADD CONSTRAINT platform_tokens_tag_length
    CHECK (octet_length(access_token_tag) = 16),
  ADD CONSTRAINT platform_tokens_key_version_positive
    CHECK (encryption_key_version BETWEEN 1 AND 2147483647),
  ADD CONSTRAINT platform_tokens_team_id_length
    CHECK (team_id IS NULL OR char_length(team_id) BETWEEN 1 AND 256),
  ADD CONSTRAINT platform_tokens_scope_length
    CHECK (scope IS NULL OR char_length(scope) BETWEEN 1 AND 4096);

-- Provider state is never stored in recoverable form. Only its SHA-256 digest
-- is persisted, and the row remains after use so the digest cannot be issued
-- again accidentally before explicit retention cleanup.
CREATE TABLE public.oauth_states (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  provider text NOT NULL CHECK (provider = 'vercel'),
  state_hash bytea NOT NULL UNIQUE CHECK (octet_length(state_hash) = 32),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  CONSTRAINT oauth_states_bounded_lifetime CHECK (
    expires_at > created_at
    AND expires_at <= created_at + interval '10 minutes'
  ),
  CONSTRAINT oauth_states_consumption_time CHECK (
    consumed_at IS NULL OR consumed_at >= created_at
  )
);

ALTER TABLE public.oauth_states ENABLE ROW LEVEL SECURITY;

CREATE INDEX oauth_states_user_expiry_idx
  ON public.oauth_states(user_id, expires_at);

-- Public Data API roles have no direct access to provider credentials or
-- OAuth state. Server code uses the service role, which remains server-only.
REVOKE ALL ON TABLE public.platform_tokens
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.oauth_states
  FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.platform_tokens
  TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.oauth_states
  TO service_role;

-- Database time fixes the issued lifetime at five minutes and avoids trusting
-- serverless-host clock skew. The state digest is already one-way before it
-- crosses the database boundary.
CREATE OR REPLACE FUNCTION public.issue_vercel_oauth_state(
  p_state_hash bytea,
  p_user_id uuid
)
RETURNS TABLE (
  state_id uuid,
  bound_user_id uuid,
  state_expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
DECLARE
  v_now timestamptz := clock_timestamp();
  v_active_states bigint;
BEGIN
  -- Serialize this RPC per user so the active-state cap remains exact even
  -- under concurrent install attempts. This lock never spans a provider call.
  PERFORM pg_advisory_xact_lock(hashtextextended(p_user_id::text, 0));

  -- Bound opportunistic retention work. Expired hashes remain for one hour,
  -- preserving a replay tombstone beyond their acceptance window; a separately
  -- commissioned global maintenance job is still required for inactive users.
  WITH stale_states AS (
    SELECT state.id
    FROM public.oauth_states AS state
    WHERE state.user_id = p_user_id
      AND state.expires_at < v_now - interval '1 hour'
    ORDER BY state.expires_at
    LIMIT 100
    FOR UPDATE
  )
  DELETE FROM public.oauth_states AS state
  USING stale_states
  WHERE state.id = stale_states.id;

  SELECT count(*)
  INTO v_active_states
  FROM public.oauth_states AS state
  WHERE state.user_id = p_user_id
    AND state.provider = 'vercel'
    AND state.consumed_at IS NULL
    AND state.expires_at > v_now;

  IF v_active_states >= 8 THEN
    RAISE EXCEPTION 'too many active Vercel OAuth states for user'
      USING ERRCODE = '54000';
  END IF;

  RETURN QUERY
  INSERT INTO public.oauth_states AS state (
    user_id,
    provider,
    state_hash,
    created_at,
    expires_at
  ) VALUES (
    p_user_id,
    'vercel',
    p_state_hash,
    v_now,
    v_now + interval '5 minutes'
  )
  RETURNING
    state.id,
    state.user_id,
    state.expires_at;
END;
$$;

REVOKE ALL ON FUNCTION public.issue_vercel_oauth_state(bytea, uuid)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.issue_vercel_oauth_state(bytea, uuid)
  TO service_role;

-- UPDATE obtains a row lock and makes the consumed_at IS NULL predicate false
-- before it returns. Concurrent callbacks therefore cannot both consume the
-- same state. Matching the authenticated Phantom user in the same statement
-- denies cross-user substitution, and database time denies expired states.
CREATE OR REPLACE FUNCTION public.consume_vercel_oauth_state(
  p_state_hash bytea,
  p_user_id uuid
)
RETURNS TABLE (
  state_id uuid,
  bound_user_id uuid,
  state_expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
DECLARE
  v_now timestamptz := clock_timestamp();
BEGIN
  RETURN QUERY
  UPDATE public.oauth_states AS state
  SET consumed_at = v_now
  WHERE state.state_hash = p_state_hash
    AND state.user_id = p_user_id
    AND state.provider = 'vercel'
    AND state.consumed_at IS NULL
    AND state.expires_at > v_now
  RETURNING state.id, state.user_id, state.expires_at;
END;
$$;

REVOKE ALL ON FUNCTION public.consume_vercel_oauth_state(bytea, uuid)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.consume_vercel_oauth_state(bytea, uuid)
  TO service_role;

COMMIT;
