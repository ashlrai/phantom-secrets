const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const webDir = path.resolve(__dirname, "..");
function compile(relativePath, localRequire) {
  const file = path.join(webDir, relativePath);
  const output = ts.transpileModule(fs.readFileSync(file, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
    fileName: file,
  }).outputText;
  const module = { exports: {} };
  new Function("exports", "require", "module", output)(module.exports, localRequire, module);
  return module.exports;
}
function harness({ admitted = true, authenticated = true, plan = "free", data = [{ outcome: "created", version: 1 }], error = null } = {}) {
  const calls = [];
  const route = compile("src/app/api/v1/vault/push/route.ts", (name) => {
    if (name === "@/lib/commissioning") return {
      requireHostedService: () => admitted ? null : Response.json({ error: "feature_unavailable" }, { status: 503 }),
    };
    if (name === "@/lib/auth") return {
      requireAuth: async () => {
        calls.push("auth");
        return authenticated ? { userId: "user-a", plan } : Response.json({ error: "unauthorized" }, { status: 401 });
      },
      requirePro: () => Response.json({ error: "feature_unavailable" }, { status: 503 }),
    };
    if (name === "@/lib/http-body") return compile("src/lib/http-body.ts", require);
    if (name === "@/lib/supabase-server") return {
      createServiceClient: () => ({
        rpc: async (...args) => { calls.push(args); return { data, error }; },
        from: () => { throw new Error("Quota and CAS must use one atomic RPC"); },
      }),
    };
    return require(name);
  });
  const push = (body = {}) => route.PUT(new Request("https://phm.dev/api/v1/vault/push", {
    method: "PUT", headers: { "content-type": "application/json" },
    body: JSON.stringify({ project_id: "project-a", encrypted_blob: "client-encrypted-fixture", expected_version: 0, ...body }),
  }));
  return { push, calls };
}

test("closed commissioning and invalid auth cause no database contact", async () => {
  const closed = harness({ admitted: false });
  assert.equal((await closed.push()).status, 503); assert.deepEqual(closed.calls, []);
  const unauthenticated = harness({ authenticated: false });
  assert.equal((await unauthenticated.push()).status, 401); assert.deepEqual(unauthenticated.calls, ["auth"]);
});
test("only authenticated identity enters the RPC, never body identity or legacy plan", async () => {
  const { push, calls } = harness({ plan: "pro" });
  const response = await push({ user_id: "user-b", p_user_id: "user-b", plan: "pro" });
  assert.equal(response.status, 201); assert.deepEqual(await response.json(), { version: 1 });
  assert.deepEqual(calls[1], ["push_personal_vault", {
    p_user_id: "user-a", p_project_id: "project-a", p_encrypted_blob: "client-encrypted-fixture", p_expected_version: 0,
  }]);
});
test("successful update preserves its receipt shape", async () => {
  const { push } = harness({ data: [{ outcome: "updated", version: 2 }] });
  const response = await push({ expected_version: 1 });
  assert.equal(response.status, 200); assert.deepEqual(await response.json(), { version: 2 });
});
test("conflicts preserve current or absent remote version", async () => {
  for (const version of [0, 3]) {
    const response = await harness({ data: [{ outcome: "conflict", version }] }).push();
    assert.equal(response.status, 409); assert.deepEqual(await response.json(), { error: "conflict", server_version: version });
  }
});
test("quota refusal stays closed for every legacy plan label", async () => {
  for (const plan of ["free", "pro"]) {
    const response = await harness({ plan, data: [{ outcome: "quota_exceeded", version: null }] }).push();
    assert.equal(response.status, 503); assert.equal((await response.json()).error, "feature_unavailable");
  }
});
test("a removed authenticated profile receives 401", async () => {
  assert.equal((await harness({ data: [{ outcome: "user_missing", version: null }] }).push()).status, 401);
});
test("database errors and malformed receipts cannot become success or conflict", async () => {
  for (const fixture of [
    { error: { message: "database failure" } }, { data: null }, { data: [] }, { data: [null] },
    { data: [{ outcome: "created", version: "1" }] }, { data: [{ outcome: "created", version: 2 }] },
    { data: [{ outcome: "updated", version: Number.MAX_SAFE_INTEGER + 1 }] },
    { data: [{ outcome: "unknown", version: 1 }] },
  ]) assert.equal((await harness(fixture).push()).status, 500);
});
test("invalid versions and byte-oversized ciphertext refuse before RPC", async () => {
  for (const expected_version of [-1, 0.1, "0", Number.MAX_SAFE_INTEGER + 1]) {
    const { push, calls } = harness();
    assert.equal((await push({ expected_version })).status, 400); assert.deepEqual(calls, ["auth"]);
  }
  const { push, calls } = harness();
  assert.equal((await push({ encrypted_blob: "é".repeat(500001) })).status, 413);
  assert.deepEqual(calls, ["auth"]);
});
