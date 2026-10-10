const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const webDir = path.resolve(__dirname, "..");
const routePath = path.join(webDir, "src/app/api/v1/auth/device/poll/route.ts");
const profile = { github_login: "synthetic-owner", email: "owner@example.invalid", plan: "free" };
const privateError = { message: "synthetic-private-database-detail", code: "XX000" };

function transpile(filePath, localRequire) {
  const source = ts.transpileModule(fs.readFileSync(filePath, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  const module = { exports: {} };
  new Function("require", "module", "exports", source)(localRequire, module, module.exports);
  return module.exports;
}

function fixture(options = {}) {
  const state = {
    token: {
      id: "synthetic-device", user_id: "synthetic-user", status: "approved",
      device_expires_at: "2099-01-01T00:00:00.000Z", token_hash: null,
      ...options.token,
    },
    profile, lookupError: null, profileError: null, claimError: null,
    claims: 0, mints: 0, writes: [], filters: [], profiles: 0,
    ...options,
  };
  const client = {
    from(table) {
      let values;
      const filters = [];
      const query = {
        select() { return this; },
        eq(key, value) { filters.push(["eq", key, value]); return this; },
        is(key, value) { filters.push(["is", key, value]); return this; },
        update(update) { values = update; return this; },
        async result() {
          if (values) {
            state.writes.push(values);
            if (!values.token_hash) return { error: null };
            state.claims++;
            state.filters.push(filters);
            if (state.claimError) return { data: null, error: state.claimError };
            assert.deepEqual(filters, [["eq", "id", "synthetic-device"], ["is", "token_hash", null]]);
            // A shared compare-and-swap model: both requests may read the
            // unclaimed snapshot, but only one can install its hash.
            if (state.token.token_hash) return { data: null, error: null };
            state.token.token_hash = values.token_hash;
            return { data: { id: state.token.id }, error: null };
          }
          if (table === "users") {
            state.profiles++;
            assert.deepEqual(filters, [["eq", "id", "synthetic-user"]]);
            if (state.profileBarrier) await state.profileBarrier();
            return { data: state.profile, error: state.profileError };
          }
          assert.deepEqual(filters, [["eq", "device_code", "synthetic-code"]]);
          return { data: state.token && { ...state.token }, error: state.lookupError };
        },
        maybeSingle() { return this.result(); },
        single() { return this.result(); },
        then(resolve, reject) { return this.result().then(resolve, reject); },
      };
      return query;
    },
  };
  const { POST } = transpile(routePath, (specifier) => {
    if (specifier === "@/lib/commissioning") return { requireHostedService: () => options.gate || null };
    if (specifier === "@/lib/supabase-server") return { createServiceClient: () => client };
    if (specifier === "@/lib/http-body") return {
      readBoundedJsonObject: (req) => req.json(),
      requestBodyErrorResponse: () => Response.json({ error: "invalid request body" }, { status: 400 }),
    };
    if (specifier === "@/lib/plan") return transpile(path.join(webDir, "src/lib/plan.ts"), require);
    if (specifier === "crypto") return {
      createHash: crypto.createHash,
      // Synthetic bytes only: no genuine credential generation in the harness.
      randomBytes: (size) => Buffer.alloc(size, ++state.mints),
    };
    throw new Error("unexpected dependency");
  });
  return { state, poll: () => POST(new Request("https://phm.dev/api/v1/auth/device/poll", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ device_code: "synthetic-code" }),
  })) };
}

async function safeError(response, message) {
  assert.equal(response.status, 500);
  assert.deepEqual(await response.json(), { error: message });
}

for (const field of ["lookupError", "profileError"]) {
  test(`${field} is a safe retryable failure without consuming the code`, async () => {
    const { state, poll } = fixture({ [field]: privateError });
    await safeError(await poll(), field === "lookupError" ? "Failed to load device authorization" : "Failed to load user");
    assert.equal(state.claims, 0);
    assert.equal(state.mints, 0);
    assert.equal(state.token.token_hash, null);
    state[field] = null;
    const response = await poll();
    assert.equal(response.status, 200);
    assert.equal((await response.json()).status, "approved");
    assert.equal(state.claims, 1);
  });
}

test("genuine absence is invalid code, not a database error", async () => {
  const { state, poll } = fixture({ token: null });
  const response = await poll();
  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), { error: "invalid device_code" });
  assert.equal(state.claims, 0);
});

test("a missing approved profile never burns the code or emits user:null", async () => {
  const { state, poll } = fixture({ profile: null });
  await safeError(await poll(), "Failed to load user");
  assert.equal(state.mints, 0);
  assert.equal(state.claims, 0);
  assert.equal(state.token.token_hash, null);
  state.profile = profile;
  assert.deepEqual((await (await poll()).json()).user, profile);
});

test("claim database failure is not falsely already_claimed; retry can succeed", async () => {
  const { state, poll } = fixture({ claimError: privateError });
  await safeError(await poll(), "Failed to claim device authorization");
  assert.equal(state.token.token_hash, null);
  state.claimError = null;
  const body = await (await poll()).json();
  assert.equal(body.status, "approved");
  assert.deepEqual(body.user, profile);
  assert.equal(state.token.token_hash, crypto.createHash("sha256").update(body.access_token).digest("hex"));
  assert.ok(state.writes.every((write) => !Object.hasOwn(write, "access_token")));
});

test("concurrent polls both read the approved snapshot but only one claims", async () => {
  let arrivals = 0;
  let release;
  const barrier = new Promise((resolve) => { release = resolve; });
  const { state, poll } = fixture({ profileBarrier: async () => {
    if (++arrivals === 2) release();
    await barrier;
  } });
  const responses = await Promise.all([poll(), poll()]);
  assert.ok(responses.every((response) => response.status === 200));
  const bodies = await Promise.all(responses.map((response) => response.json()));
  const approved = bodies.filter((body) => body.status === "approved");
  const lost = bodies.filter((body) => body.status === "already_claimed");
  assert.equal(approved.length, 1);
  assert.equal(lost.length, 1);
  assert.deepEqual(lost[0], { status: "already_claimed" });
  assert.equal(state.claims, 2);
  assert.equal(state.token.token_hash, crypto.createHash("sha256").update(approved[0].access_token).digest("hex"));
  assert.deepEqual(await (await poll()).json(), { status: "already_claimed" });
  assert.equal(state.claims, 2);
});

for (const status of ["pending", "expired"]) {
  test(`${status} does not load profile or mint credentials`, async () => {
    const { state, poll } = fixture({ token: {
      id: "synthetic-device", status, device_expires_at: "2099-01-01T00:00:00.000Z", token_hash: null,
    } });
    assert.deepEqual(await (await poll()).json(), { status });
    assert.equal(state.profiles, 0);
    assert.equal(state.mints, 0);
    assert.equal(state.claims, 0);
  });
}

test("an already claimed device needs no profile lookup", async () => {
  const { state, poll } = fixture({ token: {
    id: "synthetic-device", status: "approved", device_expires_at: "2099-01-01T00:00:00.000Z", token_hash: "synthetic-hash",
  }, profileError: privateError });
  assert.deepEqual(await (await poll()).json(), { status: "already_claimed" });
  assert.equal(state.profiles, 0);
  assert.equal(state.mints, 0);
});

test("an approved row past its device deadline cannot be claimed", async () => {
  const { state, poll } = fixture({ token: {
    id: "synthetic-device", status: "approved", device_expires_at: "2000-01-01T00:00:00.000Z", token_hash: null,
  } });
  assert.deepEqual(await (await poll()).json(), { status: "expired" });
  assert.equal(state.profiles, 0);
  assert.equal(state.mints, 0);
  assert.equal(state.claims, 0);
  assert.deepEqual(state.writes, [{ status: "expired" }]);
});
