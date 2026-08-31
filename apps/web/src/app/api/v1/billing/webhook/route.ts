import type Stripe from "stripe";
import { readBoundedText, requestBodyErrorResponse } from "@/lib/http-body";
import { getStripe, getStripeWebhookSecret } from "@/lib/stripe";
import { createServiceClient } from "@/lib/supabase-server";

const MAX_STRIPE_WEBHOOK_BYTES = 1_000_000;

type BillingEventInput = {
  p_event_id: string;
  p_event_type: string;
  p_event_created: number;
  p_claim_token: string;
  p_user_id: string | null;
  p_subscription_id: string | null;
  p_plan: "free" | "pro" | null;
  p_plan_expires_at: string | null;
};

// API 2025-04-30.basil moved current_period_end from Subscription to its items.
function getSubscriptionPeriodEnd(sub: Stripe.Subscription): number | null {
  const top = (sub as unknown as { current_period_end?: number }).current_period_end;
  if (typeof top === "number") return top;
  const item = sub.items?.data?.[0] as
    | { current_period_end?: number }
    | undefined;
  return item?.current_period_end ?? null;
}

// API 2025-04-30.basil moved subscription off Invoice onto parent.subscription_details.
function getInvoiceSubscriptionId(invoice: Stripe.Invoice): string | null {
  const direct = (invoice as unknown as {
    subscription?: string | { id: string };
  }).subscription;
  if (typeof direct === "string") return direct;
  if (direct && typeof direct === "object" && "id" in direct) return direct.id;
  const fromParent = (invoice as unknown as {
    parent?: {
      subscription_details?: { subscription?: string | { id: string } };
    };
  }).parent?.subscription_details?.subscription;
  if (typeof fromParent === "string") return fromParent;
  if (fromParent && typeof fromParent === "object" && "id" in fromParent) {
    return fromParent.id;
  }
  return null;
}

function getExpandableId(
  value: string | { id: string } | null | undefined,
): string | null {
  if (typeof value === "string") return value;
  return value?.id ?? null;
}

function billingEventInput(event: Stripe.Event): BillingEventInput | null {
  const common = {
    p_event_id: event.id,
    p_event_type: event.type,
    p_event_created: event.created,
    p_claim_token: crypto.randomUUID(),
    p_user_id: null,
    p_subscription_id: null,
    p_plan: null,
    p_plan_expires_at: null,
  } satisfies BillingEventInput;

  switch (event.type) {
    case "checkout.session.completed": {
      const session = event.data.object;
      return {
        ...common,
        p_user_id: session.metadata?.user_id ?? null,
        p_subscription_id: getExpandableId(session.subscription),
        p_plan: "pro",
      };
    }

    case "customer.subscription.updated": {
      const subscription = event.data.object;
      const periodEnd = getSubscriptionPeriodEnd(subscription);
      return {
        ...common,
        p_subscription_id: subscription.id,
        p_plan:
          subscription.status === "active" ||
          subscription.status === "trialing"
            ? "pro"
            : "free",
        p_plan_expires_at: periodEnd
          ? new Date(periodEnd * 1000).toISOString()
          : null,
      };
    }

    case "customer.subscription.deleted":
      return {
        ...common,
        p_subscription_id: event.data.object.id,
        p_plan: "free",
      };

    case "invoice.payment_failed": {
      const subscriptionId = getInvoiceSubscriptionId(event.data.object);
      return {
        ...common,
        p_subscription_id: subscriptionId,
        // Derive the deadline from the signed event time so a delayed retry
        // cannot extend the grace window indefinitely.
        p_plan_expires_at: new Date(
          (event.created + 3 * 24 * 60 * 60) * 1000,
        ).toISOString(),
      };
    }

    default:
      return null;
  }
}

export async function POST(req: Request) {
  let body: string;
  try {
    body = await readBoundedText(req, MAX_STRIPE_WEBHOOK_BYTES);
  } catch (error) {
    return requestBodyErrorResponse(error);
  }

  const signature = req.headers.get("stripe-signature");
  if (!signature) {
    return new Response("Missing signature", { status: 400 });
  }

  let event: Stripe.Event;
  try {
    event = getStripe().webhooks.constructEvent(
      body,
      signature,
      getStripeWebhookSecret(),
    );
  } catch {
    return new Response("Invalid signature", { status: 400 });
  }

  const input = billingEventInput(event);
  if (!input) return new Response("ok");

  // Claim, target resolution, ordering, billing mutation, and completion are a
  // single database transaction. A process crash or RPC error rolls all of it
  // back, so no worker can acknowledge an event whose effect did not commit.
  const { data: outcome, error } = await createServiceClient().rpc(
    "process_stripe_billing_event",
    input,
  );

  if (error) {
    return new Response("webhook processing failed", { status: 500 });
  }
  if (outcome === "busy") {
    return new Response("event already processing", { status: 409 });
  }
  if (
    outcome !== "applied" &&
    outcome !== "duplicate" &&
    outcome !== "stale" &&
    outcome !== "superseded"
  ) {
    return new Response("webhook processing failed", { status: 500 });
  }

  return new Response("ok");
}
