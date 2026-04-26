-- Phantom — team-vault envelope encryption support
--
-- Adds two columns:
--   team_members.public_key      — each member's X25519 public key (base64),
--                                  registered the first time they push or pull
--                                  a team vault. Required so other members
--                                  can encrypt the per-vault symmetric key
--                                  to them.
--   team_vault_blobs.key_shares  — JSONB { user_id: { ephemeral_pk, nonce,
--                                  ciphertext } } where each share is an
--                                  X25519 + ChaCha20-Poly1305 encryption of
--                                  the per-push symmetric key to that
--                                  member's public key. The server only
--                                  stores ciphertext — never sees the
--                                  symmetric key, never sees vault plaintext.
--
-- Backwards compatible: existing team_vault_blobs rows get an empty {}
-- and are unreadable until republished by a member who has read the old
-- blob (which is intentional — we have no plaintext to re-share).

ALTER TABLE public.team_members
  ADD COLUMN IF NOT EXISTS public_key TEXT;

ALTER TABLE public.team_vault_blobs
  ADD COLUMN IF NOT EXISTS key_shares JSONB NOT NULL DEFAULT '{}'::jsonb;

-- Index on public_key existence so the push-vault flow can fast-fail
-- when not all team members have registered keys yet.
CREATE INDEX IF NOT EXISTS team_members_with_key
  ON public.team_members(team_id)
  WHERE public_key IS NOT NULL;
