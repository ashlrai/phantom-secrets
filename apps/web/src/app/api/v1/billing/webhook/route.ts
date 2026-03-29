import { getStripe, getStripeWebhookSecret } from "@/lib/stripe";
import { createServiceClient } from "@/lib/supabase-server";

export async function POST(req: Request) {
  const body = await req.text();
  const sig = req.headers.get("stripe-signature");

  if (!sig) {
    return new Response("Missing signature", { status: 400 });
  }

  let event;
  try {
    event = getStripe().webhooks.constructEvent(body, sig, getStripeWebhookSecret());
  } catch {
    return new Response("Invalid signature", { status: 400 });
  }

  const supabase = createServiceClient();

  switch (event.type) {
    case "checkout.session.completed": {
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
      break;
    }

    case "customer.subscription.updated": {
      const sub = event.data.object;
      const { data: user } = await supabase
        .from("users")
        .select("id")
        .eq("subscription_id", sub.id)
        .single();

      if (user) {
        await supabase
          .from("users")
          .update({
            plan_expires_at: new Date(
              sub.current_period_end * 1000
            ).toISOString(),
          })
          .eq("id", user.id);
      }
      break;
    }

    case "customer.subscription.deleted": {
      const sub = event.data.object;
      await supabase
        .from("users")
        .update({
          plan: "free",
          subscription_id: null,
          plan_expires_at: null,
        })
        .eq("subscription_id", sub.id);
      break;
    }

    case "invoice.payment_failed": {
      const invoice = event.data.object;
      const subId =
        typeof invoice.subscription === "string"
          ? invoice.subscription
          : invoice.subscription?.toString();
      if (subId) {
        // Grace period: 3 days
        const grace = new Date(Date.now() + 3 * 24 * 60 * 60 * 1000);
        await supabase
          .from("users")
          .update({ plan_expires_at: grace.toISOString() })
          .eq("subscription_id", subId);
      }
      break;
    }
  }

  return new Response("ok");
}
