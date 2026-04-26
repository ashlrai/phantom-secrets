-- Phantom — platform_tokens (deployment-platform OAuth tokens)
--
-- Stores access tokens granted by Vercel, Railway, etc. when a user
-- installs the Phantom integration on their hosting account. These
-- tokens let the sync flow push secrets to platform env vars on the
-- user's behalf.
--
-- The Vercel callback at /api/v1/integrations/vercel/callback already
-- writes to this table (using `upsert` with `onConflict: user_id,platform`).
-- Without this migration the insert fails silently in production.
--
-- Note on user_id: the value written today is the platform's own
-- identifier (e.g. Vercel's user_id from the OAuth response, or the
-- literal 'pending' sentinel). Linkage to a Phantom Cloud account
-- (public.users.id) is a separate follow-up — the table is keyed
-- loosely as text for now to match the callback contract.

CREATE TABLE IF NOT EXISTS public.platform_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id text NOT NULL,
  platform text NOT NULL,                -- 'vercel', 'railway', etc.
  access_token text NOT NULL,            -- TODO: encrypt at rest before GA
  team_id text,                          -- platform-side team id (e.g. Vercel team)
  scope text,                            -- OAuth scope granted
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now(),
  UNIQUE(user_id, platform)
);

ALTER TABLE public.platform_tokens ENABLE ROW LEVEL SECURITY;

-- These tokens are platform credentials used by server-side sync flows.
-- End users never read them directly — only the service role does.
-- No policy = RLS denies all anon/authenticated access by default.

CREATE INDEX ON public.platform_tokens(user_id);
CREATE INDEX ON public.platform_tokens(platform);

CREATE TRIGGER platform_tokens_updated_at BEFORE UPDATE ON public.platform_tokens
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();
