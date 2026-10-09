-- Personal Cloud currently admits one new encrypted backup per account. Legacy
-- plan labels are not commissioned paid entitlements and never widen this cap.
-- Existing backups remain readable/updatable, including legacy over-quota rows.
CREATE OR REPLACE FUNCTION public.push_personal_vault(
  p_user_id uuid,
  p_project_id text,
  p_encrypted_blob text,
  p_expected_version bigint
)
RETURNS TABLE(outcome text, version bigint)
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
DECLARE
  v_version bigint;
BEGIN
  IF p_user_id IS NULL OR p_project_id IS NULL OR p_project_id = '' OR
     p_encrypted_blob IS NULL OR p_encrypted_blob = '' OR
     octet_length(p_encrypted_blob) > 1000000 OR
     p_expected_version IS NULL OR p_expected_version < 0 OR
     p_expected_version > 9007199254740991 THEN
    RAISE EXCEPTION 'invalid personal vault push';
  END IF;

  -- Every admitted writer locks the profile first. Different project ids for
  -- the same user must serialize before counting and creating the first vault.
  -- This matches billing's user-first lock order and needs no definer privilege.
  PERFORM 1 FROM public.users WHERE id = p_user_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'user_missing'::text, NULL::bigint;
    RETURN;
  END IF;

  SELECT blob.version INTO v_version
  FROM public.vault_blobs AS blob
  WHERE blob.user_id = p_user_id AND blob.project_id = p_project_id
  FOR UPDATE;

  IF FOUND THEN
    IF p_expected_version = 0 OR v_version <> p_expected_version THEN
      RETURN QUERY SELECT 'conflict'::text, v_version;
      RETURN;
    END IF;
    IF v_version >= 9007199254740991 THEN
      RAISE EXCEPTION 'personal vault version exceeds the API integer range';
    END IF;

    UPDATE public.vault_blobs AS blob
    SET encrypted_blob = p_encrypted_blob, version = blob.version + 1
    WHERE blob.user_id = p_user_id AND blob.project_id = p_project_id
      AND blob.version = p_expected_version
    RETURNING blob.version INTO STRICT v_version;
    RETURN QUERY SELECT 'updated'::text, v_version;
    RETURN;
  END IF;

  IF p_expected_version <> 0 THEN
    RETURN QUERY SELECT 'conflict'::text, 0::bigint;
    RETURN;
  END IF;

  IF EXISTS (SELECT 1 FROM public.vault_blobs WHERE user_id = p_user_id) THEN
    RETURN QUERY SELECT 'quota_exceeded'::text, NULL::bigint;
    RETURN;
  END IF;

  INSERT INTO public.vault_blobs (user_id, project_id, encrypted_blob, version)
  VALUES (p_user_id, p_project_id, p_encrypted_blob, 1);
  RETURN QUERY SELECT 'created'::text, 1::bigint;
END;
$$;

-- Browser sessions cannot select another user's mutation identity. Only the
-- server route supplies the UUID obtained from its validated device token.
REVOKE ALL ON FUNCTION public.push_personal_vault(uuid, text, text, bigint)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.push_personal_vault(uuid, text, text, bigint)
  TO service_role;

-- Current Supabase projects no longer promise automatic Data API grants. These
-- are the personal-Cloud operations the server actually performs. Keep browser
-- clients read-only, behind the existing ownership RLS policies; no anonymous,
-- team, or billing capability is admitted here.
GRANT SELECT, INSERT, UPDATE ON TABLE public.users TO service_role;
GRANT SELECT, UPDATE ON TABLE public.device_tokens TO service_role;
GRANT SELECT, INSERT, UPDATE ON TABLE public.vault_blobs TO service_role;
GRANT SELECT ON TABLE public.users, public.vault_blobs TO authenticated;
