-- Run only against the replayed local CI database. Fixtures are temporary and
-- the transaction is rolled back even when all assertions succeed.
BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgrelid = 'public.device_tokens'::regclass
      AND tgname = 'device_tokens_guard_claim_deadline'
      AND NOT tgisinternal
  ) THEN
    RAISE EXCEPTION 'device claim deadline trigger missing';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_proc
    WHERE oid = 'public.guard_device_claim_deadline()'::regprocedure
      AND NOT prosecdef
      AND 'search_path=pg_catalog' = ANY(proconfig)
  ) THEN
    RAISE EXCEPTION 'device claim deadline function is not invoker-safe';
  END IF;
END;
$$;

CREATE TEMP TABLE device_claim_fixture (
  id integer PRIMARY KEY,
  status text NOT NULL,
  token_hash text,
  expires_at timestamptz NOT NULL,
  device_expires_at timestamptz
);
CREATE TRIGGER device_claim_fixture_guard
BEFORE UPDATE ON device_claim_fixture
FOR EACH ROW EXECUTE FUNCTION public.guard_device_claim_deadline();

INSERT INTO device_claim_fixture VALUES
  (1, 'pending', NULL, clock_timestamp() - interval '1 second', clock_timestamp() - interval '1 second'),
  (2, 'approved', NULL, clock_timestamp() - interval '1 second', clock_timestamp() - interval '1 second'),
  (3, 'pending', NULL, clock_timestamp() + interval '1 hour', clock_timestamp() + interval '1 hour'),
  (4, 'pending', NULL, clock_timestamp() - interval '1 second', NULL);

DO $$
DECLARE
  changed integer;
BEGIN
  -- A timestamp captured before the database executes still matches WHERE.
  -- The trigger must use database time and skip the mutation itself.
  UPDATE device_claim_fixture SET status = 'approved'
    WHERE id = 1 AND device_expires_at > '2000-01-01'::timestamptz;
  GET DIAGNOSTICS changed = ROW_COUNT;
  IF changed <> 0 OR (SELECT status FROM device_claim_fixture WHERE id = 1) <> 'pending' THEN
    RAISE EXCEPTION 'expired approval succeeded after stale client predicate';
  END IF;

  UPDATE device_claim_fixture SET token_hash = 'late-token'
    WHERE id = 2 AND status = 'approved' AND token_hash IS NULL
      AND device_expires_at > '2000-01-01'::timestamptz;
  GET DIAGNOSTICS changed = ROW_COUNT;
  IF changed <> 0 OR (SELECT token_hash FROM device_claim_fixture WHERE id = 2) IS NOT NULL THEN
    RAISE EXCEPTION 'expired claim succeeded after stale client predicate';
  END IF;

  UPDATE device_claim_fixture SET status = 'approved' WHERE id = 4;
  GET DIAGNOSTICS changed = ROW_COUNT;
  IF changed <> 0 THEN
    RAISE EXCEPTION 'legacy null device deadline bypassed expires_at';
  END IF;

  UPDATE device_claim_fixture SET status = 'expired' WHERE id = 1;
  GET DIAGNOSTICS changed = ROW_COUNT;
  IF changed <> 1 THEN
    RAISE EXCEPTION 'normal expiry transition was blocked';
  END IF;
  UPDATE device_claim_fixture SET status = 'approved' WHERE id = 1;
  GET DIAGNOSTICS changed = ROW_COUNT;
  IF changed <> 0 THEN
    RAISE EXCEPTION 'expired row could be reapproved';
  END IF;

  UPDATE device_claim_fixture SET status = 'approved' WHERE id = 3;
  GET DIAGNOSTICS changed = ROW_COUNT;
  IF changed <> 1 THEN
    RAISE EXCEPTION 'valid approval was blocked';
  END IF;
  UPDATE device_claim_fixture SET token_hash = 'valid-token' WHERE id = 3;
  GET DIAGNOSTICS changed = ROW_COUNT;
  IF changed <> 1 OR (SELECT token_hash FROM device_claim_fixture WHERE id = 3) <> 'valid-token' THEN
    RAISE EXCEPTION 'valid one-use claim was blocked';
  END IF;
END;
$$;

ROLLBACK;
