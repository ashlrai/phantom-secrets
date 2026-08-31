-- Process Stripe billing events as one database transaction. The function
-- below owns claiming, user resolution, ordering, effect application, and
-- completion; an RPC failure rolls every step back together.

ALTER TABLE public.stripe_processed_events
  ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'completed',
  ADD COLUMN IF NOT EXISTS processing_token uuid,
  ADD COLUMN IF NOT EXISTS attempt_started_at timestamptz,
  ADD COLUMN IF NOT EXISTS completed_at timestamptz,
  ADD COLUMN IF NOT EXISTS event_created bigint;

UPDATE public.stripe_processed_events
SET completed_at = COALESCE(completed_at, processed_at)
WHERE status = 'completed';

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'stripe_processed_events_status_check'
      AND conrelid = 'public.stripe_processed_events'::regclass
  ) THEN
    ALTER TABLE public.stripe_processed_events
      ADD CONSTRAINT stripe_processed_events_status_check
      CHECK (status IN ('processing', 'completed', 'failed'));
  END IF;
END
$$;

CREATE INDEX IF NOT EXISTS stripe_processed_events_claim_idx
  ON public.stripe_processed_events (status, attempt_started_at);

-- Preserve historical subscription-to-user bindings. Stripe can deliver an
-- event for an old subscription after a user has started a newer one; resolving
-- through this table lets the function recognize that event as superseded.
CREATE TABLE IF NOT EXISTS public.stripe_subscription_users (
  subscription_id text PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  bound_at timestamptz NOT NULL DEFAULT now(),
  last_event_created bigint,
  last_event_priority smallint,
  last_event_id text
);

INSERT INTO public.stripe_subscription_users (subscription_id, user_id)
SELECT subscription_id, id
FROM public.users
WHERE subscription_id IS NOT NULL
ON CONFLICT (subscription_id) DO NOTHING;

ALTER TABLE public.stripe_subscription_users ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.users
  ADD COLUMN IF NOT EXISTS stripe_checkout_event_created bigint,
  ADD COLUMN IF NOT EXISTS stripe_checkout_event_id text;

-- The existing users_update_own policy is intentionally broad for profile
-- fields, so extend its billing guard before the webhook begins trusting the
-- new ordering cursor. Authenticated clients must not be able to suppress or
-- reorder server-side billing events.
CREATE OR REPLACE FUNCTION public.prevent_user_billing_self_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF current_user = 'authenticated' AND (
    NEW.plan IS DISTINCT FROM OLD.plan OR
    NEW.plan_expires_at IS DISTINCT FROM OLD.plan_expires_at OR
    NEW.stripe_customer_id IS DISTINCT FROM OLD.stripe_customer_id OR
    NEW.subscription_id IS DISTINCT FROM OLD.subscription_id OR
    NEW.stripe_checkout_event_created IS DISTINCT FROM OLD.stripe_checkout_event_created OR
    NEW.stripe_checkout_event_id IS DISTINCT FROM OLD.stripe_checkout_event_id
  ) THEN
    RAISE EXCEPTION 'billing fields are managed by Phantom server APIs';
  END IF;

  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION public.process_stripe_billing_event(
  p_event_id text,
  p_event_type text,
  p_event_created bigint,
  p_claim_token uuid,
  p_user_id uuid DEFAULT NULL,
  p_subscription_id text DEFAULT NULL,
  p_plan text DEFAULT NULL,
  p_plan_expires_at timestamptz DEFAULT NULL
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
-- The migration owner remains the definer. Only service_role receives EXECUTE,
-- and a pg_catalog-only path prevents public-schema object shadowing; every
-- application table and function reference below is schema-qualified.
SET search_path = pg_catalog
AS $$
DECLARE
  v_existing public.stripe_processed_events%ROWTYPE;
  v_binding public.stripe_subscription_users%ROWTYPE;
  v_user public.users%ROWTYPE;
  v_bound_user_id uuid;
  v_priority smallint;
  v_outcome text := 'applied';
  v_rows integer;
BEGIN
  IF p_event_id IS NULL OR p_event_id = '' OR p_event_created IS NULL OR
     p_event_created < 0 OR p_claim_token IS NULL THEN
    RAISE EXCEPTION 'invalid Stripe event identity';
  END IF;

  v_priority := CASE p_event_type
    WHEN 'checkout.session.completed' THEN 10
    WHEN 'invoice.payment_failed' THEN 20
    WHEN 'customer.subscription.updated' THEN 30
    WHEN 'customer.subscription.deleted' THEN 40
    ELSE NULL
  END;
  IF v_priority IS NULL THEN
    RAISE EXCEPTION 'unsupported Stripe billing event type';
  END IF;

  INSERT INTO public.stripe_processed_events (
    event_id, event_type, event_created, status, processing_token,
    attempt_started_at, completed_at
  ) VALUES (
    p_event_id, p_event_type, p_event_created, 'processing', p_claim_token,
    clock_timestamp(), NULL
  )
  ON CONFLICT (event_id) DO NOTHING;

  SELECT * INTO STRICT v_existing
  FROM public.stripe_processed_events
  WHERE event_id = p_event_id
  FOR UPDATE;

  IF v_existing.event_type <> p_event_type OR
     (v_existing.event_created IS NOT NULL AND
      v_existing.event_created <> p_event_created) THEN
    RAISE EXCEPTION 'Stripe event identity collision';
  END IF;
  IF v_existing.status = 'completed' THEN
    RETURN 'duplicate';
  END IF;
  IF v_existing.status = 'processing' AND
     v_existing.processing_token IS DISTINCT FROM p_claim_token AND
     v_existing.attempt_started_at > clock_timestamp() - interval '5 minutes' THEN
    RETURN 'busy';
  END IF;

  UPDATE public.stripe_processed_events
  SET event_type = p_event_type,
      event_created = p_event_created,
      status = 'processing',
      processing_token = p_claim_token,
      attempt_started_at = clock_timestamp(),
      completed_at = NULL
  WHERE event_id = p_event_id;

  IF p_event_type = 'checkout.session.completed' THEN
    IF p_user_id IS NULL OR p_subscription_id IS NULL OR p_subscription_id = '' OR
       p_plan IS DISTINCT FROM 'pro' OR p_plan_expires_at IS NOT NULL THEN
      RAISE EXCEPTION 'invalid checkout billing payload';
    END IF;

    -- Every path locks the user before the subscription binding. Keeping a
    -- single lock order prevents checkout/update concurrency from deadlocking.
    SELECT * INTO v_user
    FROM public.users
    WHERE id = p_user_id
    FOR UPDATE;
    IF NOT FOUND THEN
      -- Raising aborts the event claim as well, guaranteeing a later delivery
      -- can retry after the user mapping becomes available.
      RAISE EXCEPTION 'checkout user mapping is unavailable';
    END IF;

    INSERT INTO public.stripe_subscription_users (subscription_id, user_id)
    VALUES (p_subscription_id, p_user_id)
    ON CONFLICT (subscription_id) DO NOTHING;

    SELECT * INTO STRICT v_binding
    FROM public.stripe_subscription_users
    WHERE subscription_id = p_subscription_id
    FOR UPDATE;
    v_bound_user_id := v_binding.user_id;
    IF v_bound_user_id <> p_user_id THEN
      RAISE EXCEPTION 'subscription is already bound to another user';
    END IF;
  ELSE
    IF p_subscription_id IS NULL OR p_subscription_id = '' OR p_user_id IS NOT NULL THEN
      RAISE EXCEPTION 'invalid subscription billing payload';
    END IF;
    IF p_event_type = 'customer.subscription.updated' AND
       (p_plan IS NULL OR p_plan NOT IN ('free', 'pro')) THEN
      RAISE EXCEPTION 'invalid subscription plan';
    END IF;
    IF p_event_type = 'customer.subscription.deleted' AND
       (p_plan IS DISTINCT FROM 'free' OR p_plan_expires_at IS NOT NULL) THEN
      RAISE EXCEPTION 'invalid subscription deletion payload';
    END IF;
    IF p_event_type = 'invoice.payment_failed' AND
       (p_plan IS NOT NULL OR p_plan_expires_at IS NULL) THEN
      RAISE EXCEPTION 'invalid payment failure payload';
    END IF;

    -- Resolve the immutable binding first, lock its user, then lock and
    -- re-check the binding so every event path takes locks in the same order.
    SELECT user_id INTO v_bound_user_id
    FROM public.stripe_subscription_users
    WHERE subscription_id = p_subscription_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'subscription user mapping is unavailable';
    END IF;

    SELECT * INTO v_user
    FROM public.users
    WHERE id = v_bound_user_id
    FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'subscription user is unavailable';
    END IF;

    SELECT * INTO v_binding
    FROM public.stripe_subscription_users
    WHERE subscription_id = p_subscription_id
    FOR UPDATE;
    IF NOT FOUND OR v_binding.user_id <> v_bound_user_id THEN
      RAISE EXCEPTION 'subscription user mapping changed during processing';
    END IF;

    IF v_user.subscription_id IS DISTINCT FROM p_subscription_id THEN
      v_outcome := 'superseded';
    END IF;
  END IF;

  IF v_outcome <> 'superseded' THEN
    IF p_event_type = 'checkout.session.completed' AND (
      (v_user.stripe_checkout_event_created IS NOT NULL AND (
        v_user.stripe_checkout_event_created > p_event_created OR
        (v_user.stripe_checkout_event_created = p_event_created AND
         COALESCE(v_user.stripe_checkout_event_id, '') >= p_event_id)
      )) OR
      (v_binding.last_event_created IS NOT NULL AND (
        v_binding.last_event_created > p_event_created OR
        (v_binding.last_event_created = p_event_created AND
         COALESCE(v_binding.last_event_priority, 0) > v_priority) OR
        (v_binding.last_event_created = p_event_created AND
         COALESCE(v_binding.last_event_priority, 0) = v_priority AND
         COALESCE(v_binding.last_event_id, '') >= p_event_id)
      ))
    ) THEN
      v_outcome := 'stale';
    ELSIF p_event_type <> 'checkout.session.completed' AND
      v_binding.last_event_created IS NOT NULL AND (
        v_binding.last_event_created > p_event_created OR
        (v_binding.last_event_created = p_event_created AND
         COALESCE(v_binding.last_event_priority, 0) > v_priority) OR
        (v_binding.last_event_created = p_event_created AND
         COALESCE(v_binding.last_event_priority, 0) = v_priority AND
         COALESCE(v_binding.last_event_id, '') >= p_event_id)
      ) THEN
      v_outcome := 'stale';
    END IF;
  END IF;

  IF v_outcome = 'applied' THEN
    IF p_event_type = 'checkout.session.completed' THEN
      UPDATE public.users
      SET plan = 'pro',
          subscription_id = p_subscription_id,
          plan_expires_at = NULL,
          stripe_checkout_event_created = p_event_created,
          stripe_checkout_event_id = p_event_id
      WHERE id = p_user_id;
    ELSIF p_event_type = 'customer.subscription.updated' THEN
      UPDATE public.users
      SET plan = p_plan,
          plan_expires_at = p_plan_expires_at
      WHERE id = v_bound_user_id AND subscription_id = p_subscription_id;
    ELSIF p_event_type = 'customer.subscription.deleted' THEN
      UPDATE public.users
      SET plan = 'free',
          subscription_id = NULL,
          plan_expires_at = NULL
      WHERE id = v_bound_user_id AND subscription_id = p_subscription_id;
    ELSIF p_event_type = 'invoice.payment_failed' THEN
      UPDATE public.users
      SET plan_expires_at = p_plan_expires_at
      WHERE id = v_bound_user_id AND subscription_id = p_subscription_id;
    END IF;

    GET DIAGNOSTICS v_rows = ROW_COUNT;
    IF v_rows <> 1 THEN
      RAISE EXCEPTION 'billing update lost its locked user mapping';
    END IF;
  END IF;

  -- The ordering cursor is scoped to the subscription. This prevents an old
  -- subscription's deletion from blocking a newer checkout for a different
  -- subscription, while still making every subscription lifecycle monotonic.
  IF v_outcome IN ('applied', 'superseded') THEN
    UPDATE public.stripe_subscription_users
    SET last_event_created = p_event_created,
        last_event_priority = v_priority,
        last_event_id = p_event_id
    WHERE subscription_id = p_subscription_id
      AND (
        last_event_created IS NULL OR
        last_event_created < p_event_created OR
        (last_event_created = p_event_created AND
         COALESCE(last_event_priority, 0) < v_priority) OR
        (last_event_created = p_event_created AND
         COALESCE(last_event_priority, 0) = v_priority AND
         COALESCE(last_event_id, '') < p_event_id)
      );
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    IF v_outcome = 'applied' AND v_rows <> 1 THEN
      RAISE EXCEPTION 'subscription ordering cursor update failed';
    END IF;
  END IF;

  UPDATE public.stripe_processed_events
  SET status = 'completed',
      processing_token = NULL,
      processed_at = clock_timestamp(),
      completed_at = clock_timestamp()
  WHERE event_id = p_event_id
    AND status = 'processing'
    AND processing_token = p_claim_token;

  GET DIAGNOSTICS v_rows = ROW_COUNT;
  IF v_rows <> 1 THEN
    RAISE EXCEPTION 'Stripe event claim ownership was lost';
  END IF;

  RETURN v_outcome;
END;
$$;

REVOKE ALL ON TABLE public.stripe_processed_events FROM anon, authenticated;
REVOKE ALL ON TABLE public.stripe_subscription_users FROM anon, authenticated;
-- PostgREST can expose the RPC only to service-role requests. Browser sessions
-- cannot invoke the SECURITY DEFINER boundary directly.
REVOKE ALL ON FUNCTION public.process_stripe_billing_event(
  text, text, bigint, uuid, uuid, text, text, timestamptz
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.process_stripe_billing_event(
  text, text, bigint, uuid, uuid, text, text, timestamptz
) TO service_role;
