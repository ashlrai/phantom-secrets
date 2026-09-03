const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const webDir = path.resolve(__dirname, "..");
const routePath = path.join(
  webDir,
  "src/app/api/v1/auth/device/poll/route.ts",
);
const planPath = path.join(webDir, "src/lib/plan.ts");

function transpileModule(filePath, localRequire) {
  const output = ts.transpileModule(fs.readFileSync(filePath, "utf8"), {
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

function loadPlanModule() {
  return transpileModule(planPath, require);
}

function createServiceClient(user) {
  const calls = [];
  const token = {
    id: "device-token-1",
    user_id: "user-1",
    status: "approved",
    expires_at: "2099-01-01T00:00:00.000Z",
    device_expires_at: "2099-01-01T00:00:00.000Z",
    token_hash: null,
  };

  return {
    calls,
    from(table) {
      const query = { table, columns: null, update: null };
      const builder = {
        select(columns) {
          query.columns = columns;
          calls.push({ ...query });
          return this;
        },
        update(values) {
          query.update = values;
          return this;
        },
        eq() {
          return this;
        },
        is() {
          return this;
        },
        async single() {
          return { data: table === "device_tokens" ? token : user };
        },
        async maybeSingle() {
          return { data: { id: token.id }, error: null };
        },
      };
      return builder;
    },
  };
}

function loadRoute(serviceClient) {
  const localRequire = (specifier) => {
    if (specifier === "@/lib/commissioning") {
      return { requireHostedService: () => null };
    }
    if (specifier === "@/lib/supabase-server") {
      return { createServiceClient: () => serviceClient };
    }
    if (specifier === "@/lib/http-body") {
      return {
        readBoundedJsonObject: async (request) => request.json(),
        requestBodyErrorResponse: () =>
          Response.json({ error: "invalid request body" }, { status: 400 }),
      };
    }
    if (specifier === "@/lib/plan") return loadPlanModule();
    if (specifier === "crypto") return crypto;
    return require(specifier);
  };
  return transpileModule(routePath, localRequire);
}

test("device poll selects expiry and returns only the normalized plan", async () => {
  const serviceClient = createServiceClient({
    github_login: "octocat",
    email: "octo@example.com",
    plan: "pro",
    plan_expires_at: "not-a-date",
  });
  const { POST } = loadRoute(serviceClient);

  const response = await POST(
    new Request("https://phm.dev/api/v1/auth/device/poll", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ device_code: "device-code-1" }),
    }),
  );

  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.status, "approved");
  assert.equal(typeof body.access_token, "string");
  assert.equal(body.access_token.length, 128);
  assert.deepEqual(body.user, {
    github_login: "octocat",
    email: "octo@example.com",
    plan: "free",
  });
  assert.ok(
    serviceClient.calls.some(
      ({ table, columns }) =>
        table === "users" &&
        columns === "github_login, email, plan, plan_expires_at",
    ),
  );
});
