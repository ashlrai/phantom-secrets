import type Stripe from "stripe";
import { getStripe, getStripeWebhookSecret } from "@/lib/stripe";
import { createServiceClient } from "@/lib/supabase-server";

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

export async function POST(req: Request) {
  const body = await req.text();
  const sig = req.headers.get("stripe-signature");

  if (!sig) {
    return new Response("Missing signature", { status: 400 });
  }

  let event;
  try {
    event = getStripe().webhooks.constructEvent(
      body,
      sig,
      getStripeWebhookSecret(),
    );
  } catch {
    return new Response("Invalid signature", { status: 400 });
  }

  const supabase = createServiceClient();

  // Idempotency: short-circuit if we've already processed this event id.
  // Stripe delivers at-least-once and retries on 5xx; without this check a
  // retried event would re-apply the same plan/subscription update.
  const { error: insertErr } = await supabase
    .from("stripe_processed_events")
    .insert({ event_id: event.id, event_type: event.type });
  if (insertErr) {
    // 23505 = unique_violation → already processed, ack and return.
    if (insertErr.code === "23505") {
      return new Response("ok");
    }
    console.error(
      `[stripe-webhook] failed to record event ${event.id}:`,
      insertErr,
    );
    // Fall through and process anyway — better to double-apply than drop.
  }

  switch (event.type) {
    case "checkout.session.completed": {
      try {
        const session = event.data.object;
        const userId = session.metadata?.user_id;
        if (!userId) break;

        await supabase
          .from("users")
          .update({
            plan: "pro",
            subscription_id: session.subscription as string,
          })
          .eq("id", userId);
      } catch (err) {
        console.error(
          `[stripe-webhook] ${event.type} (${event.id}) failed:`,
          err,
        );
      }
      break;
    }

    case "customer.subscription.updated": {
      try {
        const sub = event.data.object;
        const isActive =
          sub.status === "active" || sub.status === "trialing";

        const { data: user, error } = await supabase
          .from("users")
          .select("id")
          .eq("subscription_id", sub.id)
          .single();

        if (error || !user) {
          console.warn(
            `[stripe-webhook] ${event.type} (${event.id}): no user for subscription_id=${sub.id}`,
            error,
          );
          break;
        }

        const periodEnd = getSubscriptionPeriodEnd(sub);
        const planExpiresAt = periodEnd
          ? new Date(periodEnd * 1000).toISOString()
          : null;

        await supabase
          .from("users")
          .update({
            plan: isActive ? "pro" : "free",
            plan_expires_at: planExpiresAt,
          })
          .eq("id", user.id);
      } catch (err) {
        console.error(
          `[stripe-webhook] ${event.type} (${event.id}) failed:`,
          err,
        );
      }
      break;
    }

    case "customer.subscription.deleted": {
      try {
        const sub = event.data.object;
        await supabase
          .from("users")
          .update({
            plan: "free",
            subscription_id: null,
            plan_expires_at: null,
          })
          .eq("subscription_id", sub.id);
      } catch (err) {
        console.error(
          `[stripe-webhook] ${event.type} (${event.id}) failed:`,
          err,
        );
      }
      break;
    }

    case "invoice.payment_failed": {
      try {
        const invoice = event.data.object;
        const subId = getInvoiceSubscriptionId(invoice);
        if (subId) {
          const grace = new Date(Date.now() + 3 * 24 * 60 * 60 * 1000);
          await supabase
            .from("users")
            .update({ plan_expires_at: grace.toISOString() })
            .eq("subscription_id", subId);
        }
      } catch (err) {
        console.error(
          `[stripe-webhook] ${event.type} (${event.id}) failed:`,
          err,
        );
      }
      break;
    }
  }

  return new Response("ok");
}
