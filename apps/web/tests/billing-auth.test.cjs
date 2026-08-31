const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const repoDir = path.resolve(__dirname, "..");
const authPath = path.join(repoDir, "src/lib/auth.ts");

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

  assert.match(checkout, /requireBrowserAuth/);
  assert.doesNotMatch(checkout, /requireAuth\(req\)/);
  assert.match(checkout, /customers\.search/);
  assert.match(checkout, /idempotencyKey/);
  assert.match(checkout, /phantom_user_id/);
  assert.match(checkout, /is\("stripe_customer_id", null\)/);
  assert.match(checkout, /claimed\?\.stripe_customer_id === candidateCustomerId/);
  assert.match(checkout, /user\.plan === "pro" \|\| user\.subscription_id/);
  assert.match(checkout, /subscriptions\.list/);
  assert.match(checkout, /status: "all"/);
  assert.match(checkout, /checkout\.sessions\.list/);
  assert.match(checkout, /status: "open"/);
  assert.match(checkout, /phantom-checkout-v1/);
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
  assert.match(pricing, /conflict\.error === "subscription_exists"/);
  assert.match(pricing, /window\.location\.href = "\/dashboard\/billing"/);
  assert.match(billingDashboard, /isPro \|\| hasBillingAccount/);
});
