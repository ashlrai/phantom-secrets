const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const webDir = path.resolve(__dirname, "..");
const routePath = path.join(webDir, "src/app/api/v1/auth/device/approve/route.ts");
const privateError = { message: "synthetic-private-database-detail", code: "XX000" };
const code = "ABCD-2345";

function transpile(file, dependencies = {}) {
  const output = ts.transpileModule(fs.readFileSync(file, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  const module = { exports: {} };
  new Function("require", "module", "exports", output)((name) => {
    assert.ok(name in dependencies, `Unexpected dependency ${name}`);
    return dependencies[name];
  }, module, module.exports);
  return module.exports;
}

function fixture(options = {}) {
  const state = {
    token: { id: "synthetic-device", user_code: "ABCD2345", status: "pending", device_expires_at: "2099-01-01T00:00:00.000Z", user_id: null },
    lookupError: null, approveError: null, upsertError: null,
    lookups: 0, claims: 0, upserts: 0, authCalls: 0, updates: [], filters: [],
    ...options,
  };
  let releaseLookups;
  const lookupsReady = options.concurrent ? new Promise((resolve) => { releaseLookups = resolve; }) : null;
  const service = {
    from(table) {
      let values;
      const filters = [];
      const query = {
        select() { return this; },
        eq(key, value) { filters.push(["eq", key, value]); return this; },
        gte(key, value) { filters.push(["gte", key, value]); return this; },
        order(key, value) { assert.deepEqual([key, value], ["created_at", { ascending: false }]); return this; },
        limit(value) { assert.equal(value, 1); return this; },
        upsert(update, config) { assert.equal(table, "users"); assert.deepEqual(config, { onConflict: "id" }); values = update; return this; },
        update(update) { assert.equal(table, "device_tokens"); values = update; return this; },
        async result() {
          if (table === "users") {
            state.upserts++;
            return { error: state.upsertError };
          }
          assert.equal(table, "device_tokens");
          if (values) {
            state.claims++;
            state.filters.push(filters);
            state.updates.push(values);
            assert.deepEqual(filters, [["eq", "id", "synthetic-device"], ["eq", "status", "pending"]]);
            assert.equal(values.status, "approved");
            assert.ok(Number.isFinite(Date.parse(values.approved_at)));
            if (state.approveError) {
              // A transport error may follow a committed update. The HTTP
              // response must not promise rollback or call it a lost CAS.
              if (state.commitThenError) Object.assign(state.token, values);
              return { data: state.dataWithError ? { id: state.token.id } : null, error: state.approveError };
            }
            if (state.token.status !== "pending" || state.loseCas) return { data: null, error: null };
            Object.assign(state.token, values);
            return { data: { id: state.token.id }, error: null };
          }
          state.lookups++;
          assert.deepEqual(filters.slice(0, 2), [["eq", "user_code", "ABCD2345"], ["eq", "status", "pending"]]);
          assert.equal(filters[2][0], "gte");
          assert.equal(filters[2][1], "device_expires_at");
          const token = state.token && state.token.status === "pending" && state.token.device_expires_at >= filters[2][2]
            ? { ...state.token } : null;
          if (lookupsReady) {
            if (state.lookups === 2) releaseLookups();
            await lookupsReady;
          }
          return { data: state.lookupError && !state.dataWithError ? null : token, error: state.lookupError };
        },
        maybeSingle() { return this.result(); },
        then(resolve, reject) { return this.result().then(resolve, reject); },
      };
      return query;
    },
  };
  const authDependencies = {
    "@/lib/supabase-server": { createServiceClient: () => service },
    "@/lib/plan": {},
    "./supabase-server": { createServiceClient: () => service },
    "./plan": {},
    "crypto": require("node:crypto"),
    "@supabase/supabase-js": {},
  };
  const { verifiedGithubLoginForUser } = transpile(path.join(webDir, "src/lib/auth.ts"), authDependencies);
  const { POST } = transpile(routePath, {
    "@/lib/commissioning": { requireHostedService: () => options.gate || null },
    "@/lib/supabase-server": { createServiceClient: () => service },
    "@/lib/auth": { verifiedGithubLoginForUser },
    "@/lib/device-code": transpile(path.join(webDir, "src/lib/device-code.ts")),
    "@/lib/http-body": transpile(path.join(webDir, "src/lib/http-body.ts")),
    "@supabase/supabase-js": {
      createClient(_url, _key, config) {
        state.authCalls++;
        const id = config.global.headers.Authorization.slice(7);
        return { auth: { getUser: async () => ({
          data: { user: options.unverified ? { id, user_metadata: { user_name: "forged" } } : {
            id, email: "owner@example.invalid",
            identities: [{ provider: "github", identity_data: { user_name: "synthetic-owner" } }],
          } },
          error: null,
        }) } };
      },
    },
  });
  return { state, approve: (owner = "synthetic-owner-a") => POST(new Request("https://phm.dev/api/v1/auth/device/approve", {
    method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${owner}` },
    body: JSON.stringify({ user_code: code }),
  })) };
}

async function assertSafeFailure(response, error) {
  assert.equal(response.status, 500);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.deepEqual(await response.json(), { error });
}

test("device lookup errors remain safe server failures and never claim a code", async () => {
  for (const dataWithError of [false, true]) {
    const { state, approve } = fixture({ lookupError: privateError, dataWithError });
    await assertSafeFailure(await approve(), "Failed to load device code. Please try again.");
    assert.equal(state.claims, 0);
    assert.equal(state.token.status, "pending");
  }
});

test("absent, expired, and non-pending device codes remain invalid code responses", async () => {
  for (const token of [null,
    { id: "synthetic-device", status: "pending", device_expires_at: "2000-01-01T00:00:00.000Z" },
    { id: "synthetic-device", status: "approved", device_expires_at: "2099-01-01T00:00:00.000Z" },
  ]) {
    const { state, approve } = fixture({ token });
    const response = await approve();
    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), { error: "Invalid or expired code. Please try again." });
    assert.equal(state.claims, 0);
  }
});

test("approval database errors are safe server failures even with returned data", async () => {
  for (const dataWithError of [false, true]) {
    const { state, approve } = fixture({ approveError: privateError, dataWithError });
    await assertSafeFailure(await approve(), "Unable to confirm device approval. Check your terminal before trying again.");
    assert.equal(state.claims, 1);
    assert.equal(state.token.status, "pending");
  }
});

test("an ambiguous committed approval is not mislabeled as an already-approved race", async () => {
  const { state, approve } = fixture({ approveError: privateError, commitThenError: true });
  await assertSafeFailure(await approve(), "Unable to confirm device approval. Check your terminal before trying again.");
  assert.equal(state.token.status, "approved");
  assert.equal(state.token.user_id, "synthetic-owner-a");
});

test("only an error-free zero-row compare-and-swap returns conflict", async () => {
  const { state, approve } = fixture({ loseCas: true });
  const response = await approve();
  assert.equal(response.status, 409);
  assert.deepEqual(await response.json(), { error: "Code was already approved. Please start a new login." });
  assert.equal(state.claims, 1);
});

test("concurrent owners both read pending but only one may approve or own the code", async () => {
  const { state, approve } = fixture({ concurrent: true });
  const responses = await Promise.all([approve("synthetic-owner-a"), approve("synthetic-owner-b")]);
  assert.deepEqual(responses.map((response) => response.status).sort(), [200, 409]);
  const winner = responses[0].status === 200 ? "synthetic-owner-a" : "synthetic-owner-b";
  assert.equal(state.token.user_id, winner);
  assert.equal(state.claims, 2);
  assert.equal(state.token.status, "approved");
  const bodies = await Promise.all(responses.map((response) => response.json()));
  assert.deepEqual(bodies.find((body) => body.status), { status: "approved" });
});

test("upsert failure and unverified GitHub identity still prevent all device queries", async () => {
  const failed = fixture({ upsertError: privateError });
  await assertSafeFailure(await failed.approve(), "Failed to establish the authenticated user.");
  assert.equal(failed.state.lookups, 0);
  assert.equal(failed.state.claims, 0);
  const unverified = fixture({ unverified: true });
  assert.equal((await unverified.approve()).status, 403);
  assert.equal(unverified.state.upserts, 0);
  assert.equal(unverified.state.lookups, 0);
});

test("closed hosted service performs no auth, user or device work", async () => {
  const { state, approve } = fixture({ gate: Response.json({ error: "closed" }, { status: 503 }) });
  assert.equal((await approve()).status, 503);
  assert.equal(state.authCalls, 0);
  assert.equal(state.upserts, 0);
  assert.equal(state.lookups, 0);
  assert.equal(state.claims, 0);
});
