const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const webDir = path.resolve(__dirname, "..");
const checkoutPath = path.join(
  webDir,
  "src/app/api/v1/billing/checkout/route.ts",
);
const USER_ID = "7b54bdf6-519f-485b-aa3b-18057d91c697";
const CHECKOUT_GATE_ENV = "PHANTOM_BILLING_CHECKOUT_ENABLED";
let originalCheckoutGate;
let checkoutGateCaptured = false;

function enableCommissionedCheckoutForTest() {
  if (!checkoutGateCaptured) {
    originalCheckoutGate = process.env[CHECKOUT_GATE_ENV];
    checkoutGateCaptured = true;
    test.after(() => {
      if (originalCheckoutGate === undefined) {
        delete process.env[CHECKOUT_GATE_ENV];
      } else {
        process.env[CHECKOUT_GATE_ENV] = originalCheckoutGate;
      }
    });
  }
  process.env[CHECKOUT_GATE_ENV] = "true";
}

function loadCheckoutModule({ serviceClient, stripe, userId = USER_ID }) {
  enableCommissionedCheckoutForTest();
  const source = fs.readFileSync(checkoutPath, "utf8");
  const output = ts.transpileModule(source, {
    compilerOptions: {
      esModuleInterop: true,
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
    },
    fileName: checkoutPath,
  }).outputText;

  const module = { exports: {} };
  const localRequire = (specifier) => {
    if (specifier === "@/lib/auth") {
      return { requireBrowserAuth: async () => ({ userId, plan: "free" }) };
    }
    if (specifier === "@/lib/stripe") {
      return {
        getStripe: () => stripe,
        getStripePriceId: () => "price_test_pro",
      };
    }
    if (specifier === "@/lib/supabase-server") {
      return { createServiceClient: () => serviceClient };
    }
    return require(specifier);
  };

  const fn = new Function(
    "exports",
    "require",
    "module",
    "__filename",
    "__dirname",
    output,
  );
  fn(
    module.exports,
    localRequire,
    module,
    checkoutPath,
    path.dirname(checkoutPath),
  );
  return module.exports;
}

function createServiceClient({
  user = {
    email: "octo@example.com",
    stripe_customer_id: null,
    subscription_id: null,
    plan: "free",
  },
  claimError = null,
} = {}) {
  const state = { user: user ? { ...user } : null };
  const calls = [];

  return {
    state,
    calls,
    from(table) {
      assert.equal(table, "users");
      const query = {
        operation: "select",
        update: null,
        filters: new Map(),
        nullFilters: new Set(),
      };

      const builder = {
        select(columns) {
          query.columns = columns;
          return this;
        },
        update(values) {
          query.operation = "update";
          query.update = values;
          return this;
        },
        eq(column, value) {
          query.filters.set(column, value);
          return this;
        },
        is(column, value) {
          if (value === null) query.nullFilters.add(column);
          return this;
        },
        async single() {
          calls.push({ kind: "single", query });
          return { data: state.user ? { ...state.user } : null, error: null };
        },
        async maybeSingle() {
          calls.push({ kind: "maybeSingle", query });
          if (claimError) return { data: null, error: claimError };

          const canClaim =
            state.user &&
            query.operation === "update" &&
            query.filters.get("id") === USER_ID &&
            query.nullFilters.has("stripe_customer_id") &&
            state.user.stripe_customer_id === null;
          if (!canClaim) return { data: null, error: null };

          state.user.stripe_customer_id = query.update.stripe_customer_id;
          return {
            data: { stripe_customer_id: state.user.stripe_customer_id },
            error: null,
          };
        },
      };
      return builder;
    },
  };
}

function createStripe({
  searchedCustomers = [],
  subscriptions = [],
  subscriptionListImpl = null,
  openSessions = null,
} = {}) {
  const calls = {
    customerSearch: [],
    customerCreate: [],
    subscriptionList: [],
    sessionList: [],
    sessionCreate: [],
  };
  const customerByIdempotencyKey = new Map();
  const sessionByIdempotencyKey = new Map();

  const stripe = {
    customers: {
      async search(params) {
        calls.customerSearch.push(params);
        return {
          data: searchedCustomers.map((customer) => ({ ...customer })),
        };
      },
      async create(params, options) {
        calls.customerCreate.push({ params, options });
        if (!customerByIdempotencyKey.has(options.idempotencyKey)) {
          customerByIdempotencyKey.set(
            options.idempotencyKey,
            Promise.resolve({ id: `cus_${customerByIdempotencyKey.size + 1}` }),
          );
        }
        return customerByIdempotencyKey.get(options.idempotencyKey);
      },
    },
    subscriptions: {
      async list(params) {
        calls.subscriptionList.push(params);

        if (subscriptionListImpl) {
          return subscriptionListImpl(params, calls.subscriptionList.length);
        }

        const startIndex = params.starting_after
          ? subscriptions.findIndex(({ id }) => id === params.starting_after) + 1
          : 0;
        assert.ok(
          startIndex >= 0 && (!params.starting_after || startIndex > 0),
          `unknown starting_after cursor: ${params.starting_after}`,
        );
        const data = subscriptions.slice(startIndex, startIndex + params.limit);
        return {
          data: data.map((subscription) => ({ ...subscription })),
          has_more: startIndex + data.length < subscriptions.length,
        };
      },
    },
    checkout: {
      sessions: {
        async list(params) {
          calls.sessionList.push(params);
          if (openSessions !== null) {
            return { data: openSessions.map((session) => ({ ...session })) };
          }
          const created = await Promise.all(sessionByIdempotencyKey.values());
          return { data: created.map((session) => ({ ...session })) };
        },
        async create(params, options) {
          calls.sessionCreate.push({ params, options });
          if (!sessionByIdempotencyKey.has(options.idempotencyKey)) {
            sessionByIdempotencyKey.set(
              options.idempotencyKey,
              Promise.resolve({
                id: `cs_${sessionByIdempotencyKey.size + 1}`,
                url: "https://checkout.stripe.test/session",
              }),
            );
          }
          return sessionByIdempotencyKey.get(options.idempotencyKey);
        },
      },
    },
  };

  return {
    stripe,
    calls,
    logicalCustomerCount: () => customerByIdempotencyKey.size,
    logicalSessionCount: () => sessionByIdempotencyKey.size,
  };
}

function checkoutRequest() {
  return new Request("https://phm.dev/api/v1/billing/checkout", {
    method: "POST",
  });
}

test(
  "checkout fails closed when the Stripe customer mapping cannot be persisted",
  async () => {
    const serviceClient = createServiceClient({
      claimError: new Error("database unavailable"),
    });
    const stripeHarness = createStripe();
    const { POST } = loadCheckoutModule({
      serviceClient,
      stripe: stripeHarness.stripe,
    });

    const response = await POST(checkoutRequest());

    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), {
      error: "unable to establish billing account",
    });
    assert.equal(stripeHarness.calls.customerCreate.length, 1);
    assert.equal(stripeHarness.calls.subscriptionList.length, 0);
    assert.equal(stripeHarness.calls.sessionCreate.length, 0);
    assert.equal(serviceClient.state.user.stripe_customer_id, null);
  },
);

test("concurrent and repeated checkout requests resolve to one customer and session", async () => {
  const serviceClient = createServiceClient();
  const stripeHarness = createStripe();
  const { POST } = loadCheckoutModule({
    serviceClient,
    stripe: stripeHarness.stripe,
  });

  const concurrentResponses = await Promise.all([
    POST(checkoutRequest()),
    POST(checkoutRequest()),
  ]);
  const repeatedResponse = await POST(checkoutRequest());
  const responses = [...concurrentResponses, repeatedResponse];

  for (const response of responses) {
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), {
      url: "https://checkout.stripe.test/session",
    });
  }
  assert.equal(serviceClient.state.user.stripe_customer_id, "cus_1");
  assert.equal(stripeHarness.logicalCustomerCount(), 1);
  assert.equal(stripeHarness.logicalSessionCount(), 1);
  // Both concurrent requests reach Stripe's create endpoints. The stable keys
  // make those duplicate transports resolve to one logical resource.
  assert.equal(stripeHarness.calls.customerCreate.length, 2);
  assert.equal(stripeHarness.calls.sessionCreate.length, 2);
  assert.ok(
    stripeHarness.calls.customerCreate.every(
      ({ options }) =>
        options.idempotencyKey === `phantom-customer-v1-${USER_ID}`,
    ),
  );
  assert.ok(
    stripeHarness.calls.sessionCreate.every(
      ({ options }) =>
        options.idempotencyKey === `phantom-checkout-v1-${USER_ID}`,
    ),
  );
  assert.ok(
    stripeHarness.calls.sessionCreate.every(
      ({ params }) => params.metadata.user_id === USER_ID,
    ),
  );
});

test("an existing database subscription blocks checkout before Stripe is called", async () => {
  const serviceClient = createServiceClient({
    user: {
      email: "octo@example.com",
      stripe_customer_id: "cus_existing",
      subscription_id: "sub_existing",
      plan: "free",
    },
  });
  const stripeHarness = createStripe();
  const { POST } = loadCheckoutModule({
    serviceClient,
    stripe: stripeHarness.stripe,
  });

  const response = await POST(checkoutRequest());

  assert.equal(response.status, 409);
  assert.equal((await response.json()).error, "subscription_exists");
  assert.equal(stripeHarness.calls.subscriptionList.length, 0);
  assert.equal(stripeHarness.calls.sessionList.length, 0);
  assert.equal(stripeHarness.calls.sessionCreate.length, 0);
});

test("an existing live Stripe subscription blocks checkout", async () => {
  const serviceClient = createServiceClient({
    user: {
      email: "octo@example.com",
      stripe_customer_id: "cus_existing",
      subscription_id: null,
      plan: "free",
    },
  });
  const stripeHarness = createStripe({
    subscriptions: [{ id: "sub_stripe", status: "active" }],
  });
  const { POST } = loadCheckoutModule({
    serviceClient,
    stripe: stripeHarness.stripe,
  });

  const response = await POST(checkoutRequest());

  assert.equal(response.status, 409);
  assert.equal((await response.json()).error, "subscription_exists");
  assert.deepEqual(stripeHarness.calls.subscriptionList[0], {
    customer: "cus_existing",
    status: "all",
    limit: 100,
  });
  assert.equal(stripeHarness.calls.sessionList.length, 0);
  assert.equal(stripeHarness.calls.sessionCreate.length, 0);
});

test("a live Stripe subscription on a later page blocks checkout", async () => {
  const serviceClient = createServiceClient({
    user: {
      email: "octo@example.com",
      stripe_customer_id: "cus_existing",
      subscription_id: null,
      plan: "free",
    },
  });
  const subscriptions = Array.from({ length: 101 }, (_, index) => ({
    id: `sub_${String(index + 1).padStart(3, "0")}`,
    status: index === 100 ? "active" : "canceled",
  }));
  const stripeHarness = createStripe({ subscriptions });
  const { POST } = loadCheckoutModule({
    serviceClient,
    stripe: stripeHarness.stripe,
  });

  const response = await POST(checkoutRequest());

  assert.equal(response.status, 409);
  assert.equal((await response.json()).error, "subscription_exists");
  assert.deepEqual(stripeHarness.calls.subscriptionList, [
    { customer: "cus_existing", status: "all", limit: 100 },
    {
      customer: "cus_existing",
      status: "all",
      limit: 100,
      starting_after: "sub_100",
    },
  ]);
  assert.equal(stripeHarness.calls.sessionList.length, 0);
  assert.equal(stripeHarness.calls.sessionCreate.length, 0);
});

test("checkout continues after every non-blocking Stripe subscription page", async () => {
  const serviceClient = createServiceClient({
    user: {
      email: "octo@example.com",
      stripe_customer_id: "cus_existing",
      subscription_id: null,
      plan: "free",
    },
  });
  const subscriptions = Array.from({ length: 205 }, (_, index) => ({
    id: `sub_${String(index + 1).padStart(3, "0")}`,
    status: index % 2 === 0 ? "canceled" : "incomplete_expired",
  }));
  const stripeHarness = createStripe({ subscriptions });
  const { POST } = loadCheckoutModule({
    serviceClient,
    stripe: stripeHarness.stripe,
  });

  const response = await POST(checkoutRequest());

  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    url: "https://checkout.stripe.test/session",
  });
  assert.deepEqual(
    stripeHarness.calls.subscriptionList.map(({ starting_after }) =>
      starting_after ?? null,
    ),
    [null, "sub_100", "sub_200"],
  );
  assert.equal(stripeHarness.calls.sessionList.length, 1);
  assert.equal(stripeHarness.calls.sessionCreate.length, 1);
});

test("malformed Stripe subscription pagination fails closed", async () => {
  const serviceClient = createServiceClient({
    user: {
      email: "octo@example.com",
      stripe_customer_id: "cus_existing",
      subscription_id: null,
      plan: "free",
    },
  });
  const stripeHarness = createStripe({
    subscriptionListImpl: async () => ({ data: [] }),
  });
  const { POST } = loadCheckoutModule({
    serviceClient,
    stripe: stripeHarness.stripe,
  });

  const response = await POST(checkoutRequest());

  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), {
    error: "unable_to_verify_subscription_state",
  });
  assert.equal(stripeHarness.calls.subscriptionList.length, 1);
  assert.equal(stripeHarness.calls.sessionList.length, 0);
  assert.equal(stripeHarness.calls.sessionCreate.length, 0);
});

test("non-progressing Stripe subscription pagination fails closed", async () => {
  const serviceClient = createServiceClient({
    user: {
      email: "octo@example.com",
      stripe_customer_id: "cus_existing",
      subscription_id: null,
      plan: "free",
    },
  });
  const stripeHarness = createStripe({
    subscriptionListImpl: async () => ({
      data: [{ id: "sub_repeated", status: "canceled" }],
      has_more: true,
    }),
  });
  const { POST } = loadCheckoutModule({
    serviceClient,
    stripe: stripeHarness.stripe,
  });

  const response = await POST(checkoutRequest());

  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), {
    error: "unable_to_verify_subscription_state",
  });
  assert.equal(stripeHarness.calls.subscriptionList.length, 2);
  assert.equal(stripeHarness.calls.sessionList.length, 0);
  assert.equal(stripeHarness.calls.sessionCreate.length, 0);
});

test("Stripe subscription-list errors fail closed", async () => {
  const serviceClient = createServiceClient({
    user: {
      email: "octo@example.com",
      stripe_customer_id: "cus_existing",
      subscription_id: null,
      plan: "free",
    },
  });
  const stripeHarness = createStripe({
    subscriptionListImpl: async () => {
      throw new Error("Stripe unavailable");
    },
  });
  const { POST } = loadCheckoutModule({
    serviceClient,
    stripe: stripeHarness.stripe,
  });

  const response = await POST(checkoutRequest());

  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), {
    error: "unable_to_verify_subscription_state",
  });
  assert.equal(stripeHarness.calls.sessionList.length, 0);
  assert.equal(stripeHarness.calls.sessionCreate.length, 0);
});

test("multiple open checkout sessions fail closed without creating another", async () => {
  const serviceClient = createServiceClient({
    user: {
      email: "octo@example.com",
      stripe_customer_id: "cus_existing",
      subscription_id: null,
      plan: "free",
    },
  });
  const stripeHarness = createStripe({
    subscriptions: [{ id: "sub_old", status: "canceled" }],
    openSessions: [
      { id: "cs_open_1", url: "https://checkout.stripe.test/one" },
      { id: "cs_open_2", url: "https://checkout.stripe.test/two" },
    ],
  });
  const { POST } = loadCheckoutModule({
    serviceClient,
    stripe: stripeHarness.stripe,
  });

  const response = await POST(checkoutRequest());

  assert.equal(response.status, 409);
  assert.deepEqual(await response.json(), {
    error: "multiple_open_checkout_sessions",
  });
  assert.deepEqual(stripeHarness.calls.sessionList[0], {
    customer: "cus_existing",
    status: "open",
    limit: 2,
  });
  assert.equal(stripeHarness.calls.sessionCreate.length, 0);
});
