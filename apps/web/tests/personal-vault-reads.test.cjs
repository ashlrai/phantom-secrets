const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const webDir = path.resolve(__dirname, "..");
const owner = { userId: "authenticated-owner", plan: "free" };
const profile = { github_login: "octocat", email: "owner@example.test" };
const privateError = { code: "42501", message: "private database diagnostic" };

function loadReadRoute(name, { user = { data: profile, error: null }, vault = {}, auth = owner } = {}) {
  const queries = [];
  const filename = path.join(webDir, `src/app/api/v1/${name}/route.ts`);
  const compiled = ts.transpileModule(fs.readFileSync(filename, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
    fileName: filename,
  }).outputText;
  const module = { exports: {} };
  const dependencies = {
    "@/lib/auth": { requireAuth: async () => auth },
    "@/lib/commissioning": {
      requireHostedService: () => null,
      isHostedServiceCommissioned: () => true,
    },
    "@/lib/supabase-server": {
      createServiceClient: () => ({
        from(table) {
          const query = { table, filters: [], selection: null, options: null, maybeSingle: false };
          queries.push(query);
          const result = table === "users" ? user : vault;
          return {
            select(selection, options) { query.selection = selection; query.options = options; return this; },
            eq(column, value) { query.filters.push([column, value]); return this; },
            async maybeSingle() { query.maybeSingle = true; return result; },
            then(resolve, reject) { return Promise.resolve(result).then(resolve, reject); },
          };
        },
      }),
    },
  };
  new Function("exports", "require", "module", compiled)(module.exports, (name) => {
    if (!(name in dependencies)) throw new Error(`Unexpected dependency: ${name}`);
    return dependencies[name];
  }, module);
  return { route: module.exports, queries };
}

test("account lookup distinguishes missing profile from database failure without disclosure", async () => {
  for (const [user, status, error] of [
    [{ data: null, error: null }, 404, "user not found"],
    [{ data: null, error: privateError }, 500, "Failed to load user"],
    [{ data: profile, error: privateError }, 500, "Failed to load user"],
  ]) {
    const { route, queries } = loadReadRoute("me", { user });
    const response = await route.GET(new Request("https://phm.dev/api/v1/me"));
    assert.equal(response.status, status);
    assert.deepEqual(await response.json(), { error });
    assert.equal(queries.length, 1);
    assert.deepEqual(queries[0].filters, [["id", owner.userId]]);
    assert.equal(queries[0].maybeSingle, true);
  }
});

test("vault count failures and malformed counts never fabricate a zero count", async () => {
  for (const vault of [
    { count: null, error: privateError },
    { count: 0, error: privateError },
    { count: null, error: null },
    { count: undefined, error: null },
    { count: -1, error: null },
    { count: 0.5, error: null },
    { count: Number.MAX_SAFE_INTEGER + 1, error: null },
  ]) {
    const { route, queries } = loadReadRoute("me", { vault });
    const response = await route.GET(new Request("https://phm.dev/api/v1/me"));
    assert.equal(response.status, 500);
    assert.deepEqual(await response.json(), { error: "Failed to load vault count" });
    assert.deepEqual(queries[1].filters, [["user_id", owner.userId]]);
  }
});

test("account status returns an exact successful count including legitimate zero and legacy multiple backups", async () => {
  for (const count of [0, 1, 3]) {
    const { route, queries } = loadReadRoute("me", { vault: { count, error: null } });
    const response = await route.GET(new Request("https://phm.dev/api/v1/me"));
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { ...profile, plan: "free", vaults_count: count });
    assert.deepEqual(queries[1].options, { count: "exact", head: true });
  }
});

test("pull distinguishes an absent owned backup from a database failure without returning ciphertext", async () => {
  for (const [vault, status, error] of [
    [{ data: null, error: null }, 404, "vault not found"],
    [{ data: null, error: privateError }, 500, "Failed to load vault"],
    [{ data: { encrypted_blob: "must-not-return", version: 4 }, error: privateError }, 500, "Failed to load vault"],
  ]) {
    const { route, queries } = loadReadRoute("vault/pull", { vault });
    const response = await route.GET(new Request("https://phm.dev/api/v1/vault/pull?project_id=owned-project"));
    assert.equal(response.status, status);
    assert.deepEqual(await response.json(), { error });
    assert.deepEqual(queries[0].filters, [["user_id", owner.userId], ["project_id", "owned-project"]]);
    assert.equal(queries[0].maybeSingle, true);
  }
});

test("pull returns only the successful owned encrypted backup and version", async () => {
  const vault = { data: { encrypted_blob: "encrypted-canary", version: 3 }, error: null };
  const { route } = loadReadRoute("vault/pull", { vault });
  const response = await route.GET(new Request("https://phm.dev/api/v1/vault/pull?project_id=owned-project"));
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), vault.data);
});

test("unauthenticated reads and a missing pull project never query the database", async () => {
  for (const name of ["me", "vault/pull"]) {
    const { route, queries } = loadReadRoute(name, { auth: Response.json({ error: "unauthorized" }, { status: 401 }) });
    assert.equal((await route.GET(new Request(`https://phm.dev/api/v1/${name}`))).status, 401);
    assert.deepEqual(queries, []);
  }
  const { route, queries } = loadReadRoute("vault/pull");
  const response = await route.GET(new Request("https://phm.dev/api/v1/vault/pull"));
  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), { error: "project_id required" });
  assert.deepEqual(queries, []);
});
