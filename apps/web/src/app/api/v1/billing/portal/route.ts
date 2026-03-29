import { requireAuth } from "@/lib/auth";
import { getStripe } from "@/lib/stripe";
import { createServiceClient } from "@/lib/supabase-server";

export async function POST(req: Request) {
  const authResult = await requireAuth(req);
  if (authResult instanceof Response) return authResult;

  const supabase = createServiceClient();
  const { data: user } = await supabase
    .from("users")
    .select("stripe_customer_id")
    .eq("id", authResult.userId)
    .single();

  if (!user?.stripe_customer_id) {
    return Response.json(
      { error: "No billing account. Subscribe first." },
      { status: 400 }
    );
  }

  const session = await getStripe().billingPortal.sessions.create({
    customer: user.stripe_customer_id,
    return_url: "https://phm.dev/pricing",
  });

  return Response.json({ url: session.url });
}
