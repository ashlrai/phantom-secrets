import { requireAuth } from "@/lib/auth";
import { getStripe, getStripePriceId } from "@/lib/stripe";
import { createServiceClient } from "@/lib/supabase-server";

export async function POST(req: Request) {
  const authResult = await requireAuth(req);
  if (authResult instanceof Response) return authResult;

  const supabase = createServiceClient();
  const { data: user } = await supabase
    .from("users")
    .select("email, stripe_customer_id")
    .eq("id", authResult.userId)
    .single();

  if (!user) {
    return Response.json({ error: "user not found" }, { status: 404 });
  }

  // Get or create Stripe customer
  let customerId = user.stripe_customer_id;
  if (!customerId) {
    const customer = await getStripe().customers.create({
      email: user.email ?? undefined,
      metadata: { user_id: authResult.userId },
    });
    customerId = customer.id;
    await supabase
      .from("users")
      .update({ stripe_customer_id: customerId })
      .eq("id", authResult.userId);
  }

  const session = await getStripe().checkout.sessions.create({
    customer: customerId,
    mode: "subscription",
    line_items: [{ price: getStripePriceId(), quantity: 1 }],
    success_url: "https://phm.dev/pricing?success=true",
    cancel_url: "https://phm.dev/pricing",
    metadata: { user_id: authResult.userId },
  });

  return Response.json({ url: session.url });
}
