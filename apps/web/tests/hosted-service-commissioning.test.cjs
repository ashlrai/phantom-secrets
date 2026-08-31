const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const webDir = path.resolve(__dirname, "..");
const commissioningPath = path.join(webDir, "src/lib/commissioning.ts");

const SERVICE_ENVS = {
  billing: "PHANTOM_BILLING_ENABLED",
  personal_vaults: "PHANTOM_CLOUD_VAULTS_ENABLED",
  teams: "PHANTOM_TEAMS_ENABLED",
};

function compileModule(filePath, localRequire) {
  const source = fs.readFileSync(filePath, "utf8");
  const output = ts.transpileModule(source, {
    compilerOptions: {
      esModuleInterop: true,
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
    },
    fileName: filePath,
  }).outputText;
  const module = { exports: {} };
  const fn = new Function(
    "exports",
    "require",
    "module",
    "__filename",
    "__dirname",
    output,
  );
  fn(module.exports, localRequire, module, filePath, path.dirname(filePath));
  return module.exports;
}

function loadCommissioning() {
  return compileModule(commissioningPath, (specifier) => {
    if (specifier === "server-only") return {};
    return require(specifier);
  });
}

function loadRoute(relativePath) {
  const effects = { auth: 0, body: 0, database: 0, params: 0, stripe: 0 };
  const commissioning = loadCommissioning();
  const routePath = path.join(webDir, relativePath);
  const route = compileModule(routePath, (specifier) => {
    if (specifier === "@/lib/commissioning") return commissioning;
    if (specifier === "@/lib/auth") {
      const unauthorized = async () => {
        effects.auth += 1;
        return Response.json({ error: "unauthorized" }, { status: 401 });
      };
      return {
        requireAuth: unauthorized,
        requireBrowserAuth: unauthorized,
        requirePro: () => {
          throw new Error("entitlement check must follow authentication");
        },
      };
    }
    if (specifier === "@/lib/plan") {
      return {
        effectivePlan: () => {
          throw new Error("entitlement check must follow authentication");
        },
      };
    }
    if (specifier === "@/lib/http-body") {
      return {
        readBoundedJsonObject: async () => {
          effects.body += 1;
          throw new Error("body parsing must follow authentication");
        },
        readBoundedText: async () => {
          effects.body += 1;
          return "";
        },
        requestBodyErrorResponse: () => {
          throw new Error("body errors are outside this gate test");
        },
      };
    }
    if (specifier === "@/lib/supabase-server") {
      return {
        createServiceClient: () => {
          effects.database += 1;
          throw new Error("database must follow authentication");
        },
      };
    }
    if (specifier === "@/lib/stripe") {
      const stripeEffect = () => {
        effects.stripe += 1;
        throw new Error("Stripe must follow authentication or signature validation");
      };
      return {
        getStripe: stripeEffect,
        getStripePriceId: stripeEffect,
        getStripeWebhookSecret: stripeEffect,
      };
    }
    return require(specifier);
  });

  return { effects, route };
}

function routeContext(effects, params) {
  return {
    params: {
      then(resolve, reject) {
        effects.params += 1;
        return Promise.resolve(params).then(resolve, reject);
      },
    },
  };
}

const ROUTES = [
  {
    name: "billing checkout",
    service: "billing",
    path: "src/app/api/v1/billing/checkout/route.ts",
    handler: "POST",
    request: () => new Request("https://phm.dev/api/v1/billing/checkout", { method: "POST" }),
  },
  {
    name: "billing portal",
    service: "billing",
    path: "src/app/api/v1/billing/portal/route.ts",
    handler: "POST",
    request: () => new Request("https://phm.dev/api/v1/billing/portal", { method: "POST" }),
  },
  {
    name: "personal vault push",
    service: "personal_vaults",
    path: "src/app/api/v1/vault/push/route.ts",
    handler: "PUT",
    request: () => new Request("https://phm.dev/api/v1/vault/push", { method: "PUT" }),
  },
  {
    name: "personal vault pull",
    service: "personal_vaults",
    path: "src/app/api/v1/vault/pull/route.ts",
    handler: "GET",
    request: () => new Request("https://phm.dev/api/v1/vault/pull?project_id=test"),
  },
  ...["GET", "POST"].map((handler) => ({
    name: `teams root ${handler}`,
    service: "teams",
    path: "src/app/api/v1/teams/route.ts",
    handler,
    request: () => new Request("https://phm.dev/api/v1/teams", { method: handler }),
  })),
  ...["GET", "POST"].map((handler) => ({
    name: `team members ${handler}`,
    service: "teams",
    path: "src/app/api/v1/teams/[team_id]/members/route.ts",
    handler,
    request: () => new Request("https://phm.dev/api/v1/teams/team-1/members", { method: handler }),
    params: { team_id: "team-1" },
  })),
  ...["GET", "POST"].map((handler) => ({
    name: `team keys ${handler}`,
    service: "teams",
    path: "src/app/api/v1/teams/[team_id]/key/route.ts",
    handler,
    request: () => new Request("https://phm.dev/api/v1/teams/team-1/key", { method: handler }),
    params: { team_id: "team-1" },
  })),
  ...["GET", "POST"].map((handler) => ({
    name: `team vault ${handler}`,
    service: "teams",
    path: "src/app/api/v1/teams/[team_id]/vaults/[project_id]/route.ts",
    handler,
    request: () => new Request("https://phm.dev/api/v1/teams/team-1/vaults/project-1", { method: handler }),
    params: { team_id: "team-1", project_id: "project-1" },
  })),
];

async function withOnlyGate(service, value, action) {
  const previous = new Map(
    Object.values(SERVICE_ENVS).map((env) => [env, process.env[env]]),
  );
  for (const env of Object.values(SERVICE_ENVS)) delete process.env[env];
  if (value !== undefined) process.env[SERVICE_ENVS[service]] = value;

  try {
    return await action();
  } finally {
    for (const [env, prior] of previous) {
      if (prior === undefined) delete process.env[env];
      else process.env[env] = prior;
    }
  }
}

test("all hosted API route classes deny malformed commissioning before side effects", async () => {
  for (const definition of ROUTES) {
    for (const gateValue of [undefined, "", "false", "TRUE", "1", " true "]) {
      const { route, effects } = loadRoute(definition.path);
      const args = [definition.request()];
      if (definition.params) args.push(routeContext(effects, definition.params));

      const response = await withOnlyGate(definition.service, gateValue, () =>
        route[definition.handler](...args),
      );

      assert.equal(response.status, 503, `${definition.name}: ${String(gateValue)}`);
      assert.equal(response.headers.get("cache-control"), "no-store");
      assert.deepEqual(
        await response.json(),
        {
          error: "feature_unavailable",
          service: definition.service,
          message: `${
            definition.service === "billing"
              ? "Phantom managed billing"
              : definition.service === "personal_vaults"
                ? "Phantom personal cloud vaults"
                : "Phantom hosted teams"
          } is not commissioned.`,
        },
        definition.name,
      );
      assert.deepEqual(
        effects,
        { auth: 0, body: 0, database: 0, params: 0, stripe: 0 },
        definition.name,
      );
    }
  }
});

test("only exact true lets hosted user routes advance to authentication", async () => {
  for (const definition of ROUTES) {
    const { route, effects } = loadRoute(definition.path);
    const args = [definition.request()];
    if (definition.params) args.push(routeContext(effects, definition.params));

    const response = await withOnlyGate(definition.service, "true", () =>
      route[definition.handler](...args),
    );

    assert.equal(response.status, 401, definition.name);
    assert.deepEqual(await response.json(), { error: "unauthorized" });
    assert.deepEqual(
      effects,
      { auth: 1, body: 0, database: 0, params: 0, stripe: 0 },
      definition.name,
    );
  }
});

test("billing webhook shares the exact billing gate before body, Stripe, or database work", async () => {
  for (const gateValue of [undefined, "", "false", "TRUE", "1", " true "]) {
    const { route, effects } = loadRoute("src/app/api/v1/billing/webhook/route.ts");
    const response = await withOnlyGate("billing", gateValue, () =>
      route.POST(new Request("https://phm.dev/api/v1/billing/webhook", { method: "POST" })),
    );
    assert.equal(response.status, 503, String(gateValue));
    assert.deepEqual(effects, { auth: 0, body: 0, database: 0, params: 0, stripe: 0 });
  }

  const { route, effects } = loadRoute("src/app/api/v1/billing/webhook/route.ts");
  const response = await withOnlyGate("billing", "true", () =>
    route.POST(new Request("https://phm.dev/api/v1/billing/webhook", { method: "POST" })),
  );
  assert.equal(response.status, 400);
  assert.equal(await response.text(), "Missing signature");
  assert.deepEqual(effects, { auth: 0, body: 1, database: 0, params: 0, stripe: 0 });
});

function loadMeRoute() {
  const commissioning = loadCommissioning();
  const tables = [];
  const mePath = path.join(webDir, "src/app/api/v1/me/route.ts");
  const route = compileModule(mePath, (specifier) => {
    if (specifier === "@/lib/commissioning") return commissioning;
    if (specifier === "@/lib/auth") {
      return {
        requireAuth: async () => ({ userId: "user-1", plan: "free" }),
      };
    }
    if (specifier === "@/lib/supabase-server") {
      return {
        createServiceClient: () => ({
          from(table) {
            tables.push(table);
            const builder = {
              count: table === "vault_blobs" ? 7 : undefined,
              select() {
                return this;
              },
              eq() {
                return this;
              },
              async single() {
                return {
                  data:
                    table === "users"
                      ? { github_login: "octocat", email: "octo@example.com" }
                      : null,
                };
              },
            };
            return builder;
          },
        }),
      };
    }
    return require(specifier);
  });
  return { route, tables };
}

test("CLI account status omits hosted vault metadata while its separate gate is closed", async () => {
  for (const gateValue of [undefined, "", "false", "TRUE", "1", " true "]) {
    const { route, tables } = loadMeRoute();
    const response = await withOnlyGate("personal_vaults", gateValue, () =>
      route.GET(new Request("https://phm.dev/api/v1/me")),
    );

    assert.equal(response.status, 200, String(gateValue));
    assert.deepEqual(await response.json(), {
      github_login: "octocat",
      email: "octo@example.com",
      plan: "free",
    });
    assert.deepEqual(tables, ["users"], String(gateValue));
  }

  const { route, tables } = loadMeRoute();
  const response = await withOnlyGate("personal_vaults", "true", () =>
    route.GET(new Request("https://phm.dev/api/v1/me")),
  );
  assert.equal(response.status, 200);
  assert.equal((await response.json()).vaults_count, 7);
  assert.deepEqual(tables, ["users", "vault_blobs"]);
});

test("device authorization routes remain independent of hosted-service gates", () => {
  for (const relativePath of [
    "src/app/api/v1/auth/device/initiate/route.ts",
    "src/app/api/v1/auth/device/approve/route.ts",
    "src/app/api/v1/auth/device/poll/route.ts",
  ]) {
    const source = fs.readFileSync(path.join(webDir, relativePath), "utf8");
    assert.doesNotMatch(source, /@\/lib\/commissioning|requireHostedService/);
  }
});

test("dashboard hosted data clients are guarded by server-only exact gates", () => {
  const wrappers = [
    ["src/app/dashboard/page.tsx", "personal_vaults", "./overview-client"],
    ["src/app/dashboard/projects/[id]/page.tsx", "personal_vaults", "./project-client"],
    ["src/app/dashboard/team/page.tsx", "teams", "./team-client"],
    ["src/app/dashboard/billing/page.tsx", "billing", "./billing-client"],
  ];

  for (const [relativePath, service, clientImport] of wrappers) {
    const source = fs.readFileSync(path.join(webDir, relativePath), "utf8");
    assert.match(source, /@\/lib\/commissioning/, relativePath);
    assert.match(source, new RegExp(`isHostedServiceCommissioned\\("${service}"\\)`), relativePath);
    assert.match(source, new RegExp(clientImport.replace(/[./-]/g, "\\$&")), relativePath);
    assert.doesNotMatch(source, /useSupabaseQuery|getBrowserClient/, relativePath);
  }

  const commissioning = fs.readFileSync(commissioningPath, "utf8");
  assert.match(commissioning, /^import "server-only";/);
  assert.match(commissioning, /process\.env\[HOSTED_SERVICES\[service\]\.env\] === "true"/);
});
