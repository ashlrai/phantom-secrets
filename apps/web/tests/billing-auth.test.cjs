const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const repoDir = path.resolve(__dirname, "..");
const authPath = path.join(repoDir, "src/lib/auth.ts");
const checkoutPath = path.join(
  repoDir,
  "src/app/api/v1/billing/checkout/route.ts",
);

function loadCheckoutGateHarness() {
  const source = fs.readFileSync(checkoutPath, "utf8");
  const output = ts.transpileModule(source, {
    compilerOptions: {
      esModuleInterop: true,
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
    },
    fileName: checkoutPath,
  }).outputText;

  const effects = { auth: 0, database: 0, stripe: 0 };
  const module = { exports: {} };
  const localRequire = (specifier) => {
    if (specifier === "@/lib/auth") {
      return {
        requireBrowserAuth: async () => {
          effects.auth += 1;
          return Response.json({ error: "unauthorized" }, { status: 401 });
        },
      };
    }
    if (specifier === "@/lib/commissioning") {
      return {
        requireHostedService: () => {
          if (process.env.PHANTOM_BILLING_ENABLED === "true") return null;
          return Response.json(
            {
              error: "feature_unavailable",
              service: "billing",
              message: "Phantom managed billing is not commissioned.",
            },
            { status: 503, headers: { "cache-control": "no-store" } },
          );
        },
      };
    }
    if (specifier === "@/lib/stripe") {
      return {
        getStripe: () => {
          effects.stripe += 1;
          throw new Error("Stripe must not be reached by the gate test");
        },
        getStripePriceId: () => {
          effects.stripe += 1;
          throw new Error(
            "Stripe price lookup must not be reached by the gate test",
          );
        },
      };
    }
    if (specifier === "@/lib/supabase-server") {
      return {
        createServiceClient: () => {
          effects.database += 1;
          throw new Error("Database must not be reached by the gate test");
        },
      };
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

  return { checkout: module.exports, effects };
}

async function withCheckoutGate(value, action) {
  const envName = "PHANTOM_BILLING_ENABLED";
  const previous = process.env[envName];
  if (value === undefined) {
    delete process.env[envName];
  } else {
    process.env[envName] = value;
  }

  try {
    return await action();
  } finally {
    if (previous === undefined) {
      delete process.env[envName];
    } else {
      process.env[envName] = previous;
    }
  }
}

function loadAuthModule({ serviceClient, browserUser = null, browserError = null }) {
  const source = fs.readFileSync(authPath, "utf8");
  const output = ts.transpileModule(source, {
    compilerOptions: {
      esModuleInterop: true,
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
    },
    fileName: authPath,
  }).outputText;

  const createClientCalls = [];
  const module = { exports: {} };
  const localRequire = (specifier) => {
    if (specifier === "./supabase-server") {
      return { createServiceClient: () => serviceClient };
    }
    if (specifier === "@supabase/supabase-js") {
      return {
        createClient: (...args) => {
          createClientCalls.push(args);
          return {
            auth: {
              getUser: async () => ({
                data: { user: browserUser },
                error: browserError,
              }),
            },
          };
        },
      };
    }
    if (specifier === "crypto") return crypto;
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
  fn(module.exports, localRequire, module, authPath, path.dirname(authPath));

  return { auth: module.exports, createClientCalls };
}

function createMockServiceClient({
  deviceToken = null,
  usersById = {},
  upsertError = null,
} = {}) {
  const calls = [];

  return {
    calls,
    from(table) {
      const filters = new Map();
      return {
        select() {
          return this;
        },
        eq(column, value) {
          filters.set(column, value);
          return this;
        },
        async single() {
          if (table === "device_tokens") {
            const wantedHash = filters.get("token_hash");
            return {
              data:
                deviceToken && deviceToken.token_hash === wantedHash
                  ? deviceToken
                  : null,
            };
          }
          if (table === "users") {
            return { data: usersById[filters.get("id")] ?? null };
          }
          return { data: null };
        },
        async upsert(row, options) {
          calls.push({ table, row, options });
          if (!upsertError && table === "users" && !usersById[row.id]) {
            usersById[row.id] = {
              plan: "free",
              plan_expires_at: null,
            };
          }
          return { error: upsertError };
        },
      };
    },
  };
}

test("device auth still validates hashed Phantom device tokens", async () => {
  const token = "cli-device-token";
  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
  const serviceClient = createMockServiceClient({
    deviceToken: {
      user_id: "user-device",
      status: "approved",
      expires_at: "2099-01-01T00:00:00.000Z",
      token_expires_at: "2099-01-01T00:00:00.000Z",
      token_hash: tokenHash,
    },
    usersById: {
      "user-device": {
        plan: "pro",
        plan_expires_at: "2000-01-01T00:00:00.000Z",
      },
    },
  });
  const { auth } = loadAuthModule({ serviceClient });

  const result = await auth.authenticateRequest(
    new Request("https://phm.dev/api/v1/me", {
      headers: { authorization: `Bearer ${token}` },
    }),
  );

  assert.deepEqual(result, { userId: "user-device", plan: "free" });
});

test("device auth does not accept browser-only bearer tokens", async () => {
  const serviceClient = createMockServiceClient();
  const { auth } = loadAuthModule({ serviceClient });

  const result = await auth.authenticateRequest(
    new Request("https://phm.dev/api/v1/me", {
      headers: { authorization: "Bearer browser-session-token" },
    }),
  );

  assert.equal(result, null);
});

test("browser auth validates Supabase sessions and upserts public user rows", async () => {
  process.env.NEXT_PUBLIC_SUPABASE_URL = "https://supabase.test";
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = "anon";

  const serviceClient = createMockServiceClient({
    usersById: {
      "user-browser": {
        plan: "pro",
        plan_expires_at: "2099-01-01T00:00:00.000Z",
      },
    },
  });
  const { auth, createClientCalls } = loadAuthModule({
    serviceClient,
    browserUser: {
      id: "user-browser",
      email: "octo@example.com",
      identities: [
        {
          provider: "github",
          identity_data: { user_name: "OctoCat" },
        },
      ],
      user_metadata: { user_name: "attacker-controlled" },
    },
  });

  const result = await auth.authenticateBrowserRequest(
    new Request("https://phm.dev/api/v1/billing/checkout", {
      headers: { authorization: "Bearer browser-session-token" },
    }),
  );

  assert.deepEqual(result, { userId: "user-browser", plan: "pro" });
  assert.equal(createClientCalls[0][0], "https://supabase.test");
  assert.equal(
    createClientCalls[0][2].global.headers.Authorization,
    "Bearer browser-session-token",
  );
  assert.deepEqual(serviceClient.calls[0], {
    table: "users",
    row: {
      id: "user-browser",
      github_login: "octocat",
      email: "octo@example.com",
    },
    options: { onConflict: "id" },
  });
});

test("browser auth rejects mutable metadata without a verified GitHub identity", async () => {
  process.env.NEXT_PUBLIC_SUPABASE_URL = "https://supabase.test";
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = "anon";

  const serviceClient = createMockServiceClient();
  const { auth } = loadAuthModule({
    serviceClient,
    browserUser: {
      id: "user-attacker",
      email: "attacker@example.com",
      identities: [],
      user_metadata: { user_name: "octocat" },
    },
  });

  const result = await auth.authenticateBrowserRequest(
    new Request("https://phm.dev/api/v1/billing/checkout", {
      headers: { authorization: "Bearer browser-session-token" },
    }),
  );

  assert.equal(result, null);
  assert.equal(serviceClient.calls.length, 0);
});

test("billing routes opt into browser auth without widening CLI API routes", () => {
  const checkout = fs.readFileSync(
    path.join(repoDir, "src/app/api/v1/billing/checkout/route.ts"),
    "utf8",
  );
  const portal = fs.readFileSync(
    path.join(repoDir, "src/app/api/v1/billing/portal/route.ts"),
    "utf8",
  );
  const vaultPush = fs.readFileSync(
    path.join(repoDir, "src/app/api/v1/vault/push/route.ts"),
    "utf8",
  );
  const commissioning = fs.readFileSync(
    path.join(repoDir, "src/lib/commissioning.ts"),
    "utf8",
  );

  assert.match(checkout, /requireBrowserAuth/);
  assert.doesNotMatch(checkout, /requireAuth\(req\)/);
  assert.match(checkout, /customers\.search/);
  assert.match(checkout, /idempotencyKey/);
  assert.match(checkout, /phantom_user_id/);
  assert.match(checkout, /is\("stripe_customer_id", null\)/);
  assert.match(checkout, /claimed\?\.stripe_customer_id === candidateCustomerId/);
  assert.match(checkout, /hasActiveLegacyProPlan\(user\) \|\| user\.subscription_id/);
  assert.match(checkout, /subscriptions\.list/);
  assert.match(checkout, /status: "all"/);
  assert.match(checkout, /checkout\.sessions\.list/);
  assert.match(checkout, /status: "open"/);
  assert.match(checkout, /phantom-checkout-v1/);
  assert.match(checkout, /requireHostedService\("billing"\)/);
  assert.match(portal, /requireHostedService\("billing"\)/);
  assert.match(commissioning, /PHANTOM_BILLING_ENABLED/);
  assert.match(commissioning, /=== "true"/);
  assert.ok(
    checkout.indexOf('requireHostedService("billing")') <
      checkout.indexOf("requireBrowserAuth(req)"),
    "commissioning gate must run before authentication",
  );
  assert.match(portal, /requireBrowserAuth/);
  assert.doesNotMatch(portal, /requireAuth\(req\)/);
  assert.match(vaultPush, /requireAuth\(req\)/);
  assert.doesNotMatch(vaultPush, /requireBrowserAuth/);

  const pricing = fs.readFileSync(
    path.join(repoDir, "src/app/pricing/page.tsx"),
    "utf8",
  );
  const billingDashboard = fs.readFileSync(
    path.join(repoDir, "src/app/dashboard/billing/page.tsx"),
    "utf8",
  );
  assert.doesNotMatch(pricing, /\/api\/v1\/billing\/checkout/);
  assert.doesNotMatch(pricing, /signInWithOAuth/);
  assert.doesNotMatch(pricing, /subscription_exists/);
  assert.doesNotMatch(pricing, /Start with Pro/);
  assert.match(
    pricing,
    /Pro billing and cloud entitlements are not commissioned/,
  );
  assert.match(pricing, /Join the Pro pilot list/);
  assert.match(
    pricing,
    /mailto:mason@ashlr\.ai\?subject=Phantom%20Pro%20pilot/,
  );
  assert.doesNotMatch(
    billingDashboard,
    /\/api\/v1\/billing\/(?:checkout|portal)/,
  );
  assert.match(
    billingDashboard,
    /does not collect payment or start a\s+subscription/,
  );
});

test(
  "checkout commissioning gate denies before every downstream side effect",
  async () => {
    for (const gateValue of [undefined, "", "false", "TRUE", "1", " true "]) {
      const { checkout, effects } = loadCheckoutGateHarness();
      const response = await withCheckoutGate(gateValue, () =>
        checkout.POST(
          new Request("https://phm.dev/api/v1/billing/checkout", {
            method: "POST",
          }),
        ),
      );

      assert.equal(response.status, 503, String(gateValue));
      const body = await response.json();
      assert.deepEqual(
        body,
        {
          error: "feature_unavailable",
          service: "billing",
          message: "Phantom managed billing is not commissioned.",
        },
        String(gateValue),
      );
      assert.equal("checkout_url" in body, false, String(gateValue));
      assert.deepEqual(
        effects,
        { auth: 0, database: 0, stripe: 0 },
        String(gateValue),
      );
    }
  },
);

test("only exact true advances checkout as far as authentication", async () => {
  const { checkout, effects } = loadCheckoutGateHarness();
  const response = await withCheckoutGate("true", () =>
    checkout.POST(
      new Request("https://phm.dev/api/v1/billing/checkout", {
        method: "POST",
      }),
    ),
  );

  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { error: "unauthorized" });
  assert.deepEqual(effects, { auth: 1, database: 0, stripe: 0 });
});

test("dashboard and auth do not present uncommissioned Pro billing as live", () => {
  const billingDashboard = fs.readFileSync(
    path.join(repoDir, "src/app/dashboard/billing/page.tsx"),
    "utf8",
  );
  const dashboardOverview = fs.readFileSync(
    path.join(repoDir, "src/app/dashboard/page.tsx"),
    "utf8",
  );
  const auth = fs.readFileSync(authPath, "utf8");
  const dashboardClaims = `${billingDashboard}\n${dashboardOverview}`;
  const plannedProSurfaces = `${dashboardClaims}\n${auth}`;

  for (const activeClaim of [
    /Upgrade to Pro/i,
    /\$\s*8\s*(?:\/|per\s+)\s*(?:mo(?:nth)?|month)/i,
    /unlimited cloud vaults?/i,
    /priority[\s-]+support/i,
  ]) {
    assert.doesNotMatch(plannedProSurfaces, activeClaim);
  }

  for (const activeBillingUi of [
    /\/api\/v1\/billing\/(?:checkout|portal)/i,
    /signInWithOAuth/i,
    /Manage billing in Stripe/i,
    /Opening Stripe/i,
    /Renews on/i,
    /Receipt \+ invoices/i,
    /Past invoices, payment methods/i,
  ]) {
    assert.doesNotMatch(dashboardClaims, activeBillingUi);
  }

  assert.match(billingDashboard, /planned|not commissioned|uncommissioned/i);
  assert.match(billingDashboard, /mailto:|contact/i);
  assert.match(dashboardOverview, /pilot|planned|not commissioned|uncommissioned/i);

  assert.doesNotMatch(auth, /checkout_url/i);
  assert.match(auth, /not commissioned|uncommissioned|unavailable/i);
  assert.match(auth, /status:\s*503/);
});

test("planned Pro authorization fails closed for every stored plan label", async () => {
  const { auth } = loadAuthModule({
    serviceClient: createMockServiceClient(),
  });

  for (const plan of ["free", "pro"]) {
    const response = auth.requirePro({ userId: `user-${plan}`, plan });
    assert.ok(response instanceof Response, plan);
    assert.equal(response.status, 503, plan);

    const body = await response.json();
    assert.equal(body.error, "feature_unavailable", plan);
    assert.match(body.message, /not commissioned/i, plan);
    assert.match(body.interest_url, /^mailto:/i, plan);
    assert.equal("checkout_url" in body, false, plan);
    assert.doesNotMatch(JSON.stringify(body), /\$\s*8|per month|\/month/i, plan);
  }
});
