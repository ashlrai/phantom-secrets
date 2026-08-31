import { requireBrowserAuth } from "@/lib/auth";
import { getStripe, getStripePriceId } from "@/lib/stripe";
import { createServiceClient } from "@/lib/supabase-server";

const BILLING_CHECKOUT_ENABLED_ENV = "PHANTOM_BILLING_CHECKOUT_ENABLED";
const SUBSCRIPTION_PAGE_SIZE = 100;
const MAX_SUBSCRIPTION_PAGES = 100;

type BillingUser = {
  email: string | null;
  stripe_customer_id: string | null;
  subscription_id: string | null;
  plan: string;
};

function subscriptionExistsResponse() {
  return Response.json(
    {
      error: "subscription_exists",
      message: "Manage the existing subscription from the billing portal.",
    },
    { status: 409 },
  );
}

function subscriptionStateUnavailableResponse() {
  return Response.json(
    { error: "unable_to_verify_subscription_state" },
    { status: 503 },
  );
}

async function hasBlockingSubscription(customerId: string): Promise<boolean> {
  const stripe = getStripe();
  let startingAfter: string | undefined;
  const seenCursors = new Set<string>();

  for (let pageNumber = 0; pageNumber < MAX_SUBSCRIPTION_PAGES; pageNumber += 1) {
    const page = await stripe.subscriptions.list({
      customer: customerId,
      status: "all",
      limit: SUBSCRIPTION_PAGE_SIZE,
      ...(startingAfter ? { starting_after: startingAfter } : {}),
    });

    // Stripe's SDK types guarantee this shape at compile time, but the route
    // must still fail closed if a proxy or upstream response is malformed.
    if (!page || !Array.isArray(page.data) || typeof page.has_more !== "boolean") {
      throw new Error("malformed Stripe subscription page");
    }

    if (
      page.data.some(
        ({ status }) => status !== "canceled" && status !== "incomplete_expired",
      )
    ) {
      return true;
    }

    if (!page.has_more) return false;

    const nextCursor = page.data.at(-1)?.id;
    if (!nextCursor || nextCursor === startingAfter || seenCursors.has(nextCursor)) {
      throw new Error("Stripe subscription pagination did not advance");
    }

    seenCursors.add(nextCursor);
    startingAfter = nextCursor;
  }

  throw new Error("Stripe subscription pagination exceeded safety limit");
}

async function persistCustomerMapping(
  supabase: ReturnType<typeof createServiceClient>,
  userId: string,
  candidateCustomerId: string,
): Promise<string> {
  const { data: claimed, error: claimError } = await supabase
    .from("users")
    .update({ stripe_customer_id: candidateCustomerId })
    .eq("id", userId)
    .is("stripe_customer_id", null)
    .select("stripe_customer_id")
    .maybeSingle();

  if (claimError) {
    throw new Error("failed to persist Stripe customer mapping");
  }

  if (claimed?.stripe_customer_id === candidateCustomerId) {
    return candidateCustomerId;
  }

  // A concurrent checkout may have won the conditional update. Re-read and
  // require an exact match before creating a session so billing can never run
  // against a customer that is not durably bound to this Phantom user.
  const { data: current, error: readError } = await supabase
    .from("users")
    .select("stripe_customer_id")
    .eq("id", userId)
    .single();

  if (readError || current?.stripe_customer_id !== candidateCustomerId) {
    throw new Error("conflicting Stripe customer mapping");
  }

  return candidateCustomerId;
}

async function getOrCreateCustomerId(
  supabase: ReturnType<typeof createServiceClient>,
  userId: string,
  user: BillingUser,
): Promise<string> {
  if (user.stripe_customer_id) return user.stripe_customer_id;

  const stripe = getStripe();
  const matches = await stripe.customers.search({
    query: `metadata['phantom_user_id']:'${userId}'`,
    limit: 2,
  });

  if (matches.data.length > 1) {
    throw new Error("multiple Stripe customers claim this Phantom user");
  }

  const customerId = matches.data[0]?.id ?? (
    await stripe.customers.create(
      {
        email: user.email ?? undefined,
        metadata: {
          phantom_user_id: userId,
          user_id: userId,
        },
      },
      // Concurrent requests receive one Stripe customer. A later retry can
      // recover the same customer through metadata search even after Stripe's
      // idempotency-key retention window expires.
      { idempotencyKey: `phantom-customer-v1-${userId}` },
    )
  ).id;

  return persistCustomerMapping(supabase, userId, customerId);
}

export async function POST(req: Request) {
  // Checkout is a separately commissioned production capability. Keep this
  // exact and fail closed: missing, malformed, or loosely truthy values must
  // not reach authentication, the database, or Stripe.
  if (process.env[BILLING_CHECKOUT_ENABLED_ENV] !== "true") {
    return Response.json(
      {
        error: "feature_unavailable",
        message: "Phantom Pro checkout is not commissioned.",
      },
      { status: 503 },
    );
  }

  const authResult = await requireBrowserAuth(req);
  if (authResult instanceof Response) return authResult;

  const supabase = createServiceClient();
  const { data: user } = await supabase
    .from("users")
    .select("email, stripe_customer_id, subscription_id, plan")
    .eq("id", authResult.userId)
    .single();

  if (!user) {
    return Response.json({ error: "user not found" }, { status: 404 });
  }

  if (user.plan === "pro" || user.subscription_id) {
    return subscriptionExistsResponse();
  }

  let customerId: string;
  try {
    customerId = await getOrCreateCustomerId(
      supabase,
      authResult.userId,
      user,
    );
  } catch {
    return Response.json(
      { error: "unable to establish billing account" },
      { status: 503 },
    );
  }

  let blockingSubscription: boolean;
  try {
    blockingSubscription = await hasBlockingSubscription(customerId);
  } catch {
    return subscriptionStateUnavailableResponse();
  }
  if (blockingSubscription) {
    return subscriptionExistsResponse();
  }

  const stripe = getStripe();
  // Reuse the one outstanding session instead of creating parallel purchase
  // paths. Stripe's per-user idempotency key closes the concurrent-request
  // window before this session becomes visible to the list API.
  const openSessions = await stripe.checkout.sessions.list({
    customer: customerId,
    status: "open",
    limit: 2,
  });
  if (openSessions.data.length > 1) {
    return Response.json(
      { error: "multiple_open_checkout_sessions" },
      { status: 409 },
    );
  }
  if (openSessions.data[0]?.url) {
    return Response.json({ url: openSessions.data[0].url });
  }

  const session = await stripe.checkout.sessions.create(
    {
      customer: customerId,
      mode: "subscription",
      line_items: [{ price: getStripePriceId(), quantity: 1 }],
      success_url: "https://phm.dev/pricing?success=true",
      cancel_url: "https://phm.dev/pricing",
      metadata: { user_id: authResult.userId },
    },
    { idempotencyKey: `phantom-checkout-v1-${authResult.userId}` },
  );

  return Response.json({ url: session.url });
}
