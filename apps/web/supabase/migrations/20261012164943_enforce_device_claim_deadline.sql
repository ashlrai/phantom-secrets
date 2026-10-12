-- A device-code deadline must be checked when the row is actually mutated.
-- API-side timestamps can be stale while a request waits for a database lock.
CREATE FUNCTION public.guard_device_claim_deadline()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
BEGIN
  IF (
    (NEW.status = 'approved' AND OLD.status IS DISTINCT FROM NEW.status)
    OR (OLD.token_hash IS NULL AND NEW.token_hash IS NOT NULL)
  ) AND COALESCE(OLD.device_expires_at, OLD.expires_at) <= clock_timestamp() THEN
    -- Skipping the row gives PostgREST an empty UPDATE result, preserving the
    -- routes' existing conflict/already-claimed responses without issuing a token.
    RETURN NULL;
  END IF;

  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION public.guard_device_claim_deadline() FROM PUBLIC, anon, authenticated;

CREATE TRIGGER device_tokens_guard_claim_deadline
BEFORE UPDATE ON public.device_tokens
FOR EACH ROW EXECUTE FUNCTION public.guard_device_claim_deadline();
