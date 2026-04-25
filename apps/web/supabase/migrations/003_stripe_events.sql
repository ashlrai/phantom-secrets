-- Phantom Pro — Stripe Webhook Idempotency
-- Records the id of every Stripe event we successfully process so the
-- webhook handler can short-circuit duplicate deliveries (Stripe retries
-- on 5xx and on its own internal at-least-once guarantees).

CREATE TABLE IF NOT EXISTS public.stripe_processed_events (
  event_id     text PRIMARY KEY,
  event_type   text NOT NULL,
  processed_at timestamptz NOT NULL DEFAULT now()
);

-- Service-role only; never read or written by clients.
ALTER TABLE public.stripe_processed_events ENABLE ROW LEVEL SECURITY;

-- Bound table size — events older than 30 days are useless for dedup.
CREATE INDEX IF NOT EXISTS stripe_processed_events_processed_at_idx
  ON public.stripe_processed_events (processed_at);
