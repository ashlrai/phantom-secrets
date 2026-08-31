const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const repoDir = path.resolve(__dirname, "..");
const helperPath = path.join(repoDir, "src/lib/http-body.ts");

function loadBodyHelper() {
  const source = fs.readFileSync(helperPath, "utf8");
  const output = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
    },
    fileName: helperPath,
  }).outputText;
  const module = { exports: {} };
  new Function("exports", "require", "module", output)(
    module.exports,
    require,
    module,
  );
  return module.exports;
}

const body = loadBodyHelper();

test("bounded JSON accepts an object at the exact byte limit", async () => {
  const payload = JSON.stringify({ key: "value" });
  const request = new Request("https://phm.dev/test", {
    method: "POST",
    body: payload,
  });
  assert.deepEqual(
    await body.readBoundedJsonObject(request, Buffer.byteLength(payload)),
    { key: "value" },
  );
});

test("declared and streamed oversized bodies fail with 413", async () => {
  const declared = new Request("https://phm.dev/test", {
    method: "POST",
    headers: { "content-length": "100" },
    body: "small",
  });
  await assert.rejects(
    body.readBoundedText(declared, 10),
    (error) => error.status === 413 && error.code === "body_too_large",
  );

  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(8));
      controller.enqueue(new Uint8Array(8));
      controller.close();
    },
  });
  const streamed = new Request("https://phm.dev/test", {
    method: "POST",
    body: stream,
    duplex: "half",
  });
  await assert.rejects(
    body.readBoundedText(streamed, 10),
    (error) => error.status === 413 && error.code === "body_too_large",
  );
});

test("malformed length, invalid UTF-8, and non-object JSON fail closed", async () => {
  const malformedLength = new Request("https://phm.dev/test", {
    method: "POST",
    headers: { "content-length": "1e6" },
    body: "{}",
  });
  await assert.rejects(
    body.readBoundedText(malformedLength, 100),
    (error) => error.status === 400 && error.code === "invalid_body",
  );

  const invalidUtf8 = new Request("https://phm.dev/test", {
    method: "POST",
    body: new Uint8Array([0xc3, 0x28]),
  });
  await assert.rejects(
    body.readBoundedText(invalidUtf8, 100),
    (error) => error.status === 400 && error.code === "invalid_body",
  );

  const arrayJson = new Request("https://phm.dev/test", {
    method: "POST",
    body: "[]",
  });
  await assert.rejects(
    body.readBoundedJsonObject(arrayJson, 100),
    (error) => error.status === 400 && error.code === "invalid_body",
  );
});

test("every JSON API body uses the bounded reader", () => {
  const apiRoot = path.join(repoDir, "src/app/api");
  const stack = [apiRoot];
  const offenders = [];
  while (stack.length) {
    const current = stack.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const target = path.join(current, entry.name);
      if (entry.isDirectory()) stack.push(target);
      if (entry.isFile() && entry.name === "route.ts") {
        const source = fs.readFileSync(target, "utf8");
        if (/req\.(json|text)\s*\(/.test(source)) {
          offenders.push(path.relative(repoDir, target));
        }
      }
    }
  }
  assert.deepEqual(offenders, []);
});

test("Stripe webhook delegates the entire lifecycle to one guarded RPC", () => {
  const route = fs.readFileSync(
    path.join(repoDir, "src/app/api/v1/billing/webhook/route.ts"),
    "utf8",
  );
  const migration = fs.readFileSync(
    path.join(
      repoDir,
      "supabase/migrations/20260831010000_stripe_event_processing_state.sql",
    ),
    "utf8",
  );

  assert.match(route, /\.rpc\(\s*"process_stripe_billing_event"/s);
  assert.doesNotMatch(route, /\.from\("(?:users|stripe_processed_events)"\)/);
  assert.match(route, /status:\s*500/);
  assert.match(route, /outcome === "busy"/);
  assert.match(route, /event\.created \+ 3 \* 24 \* 60 \* 60/);

  assert.match(migration, /SECURITY DEFINER/);
  assert.match(migration, /SET search_path = pg_catalog\s*\n/);
  assert.doesNotMatch(migration, /SET search_path = pg_catalog, public/);
  assert.match(migration, /FOR UPDATE/);
  assert.match(migration, /processing_token = p_claim_token/);
  assert.match(migration, /AND processing_token = p_claim_token/);
  assert.match(migration, /GET DIAGNOSTICS v_rows = ROW_COUNT/);
  assert.match(migration, /billing update lost its locked user mapping/);
  assert.match(migration, /CHECK \(status IN \('processing', 'completed', 'failed'\)\)/);
  assert.match(migration, /ADD COLUMN IF NOT EXISTS processing_token uuid/);
  assert.match(migration, /CREATE TABLE IF NOT EXISTS public\.stripe_subscription_users/);
  assert.match(migration, /subscription user mapping is unavailable/);
  assert.match(migration, /v_user\.subscription_id IS DISTINCT FROM p_subscription_id/);
  assert.match(migration, /stripe_checkout_event_created > p_event_created/);
  assert.match(
    migration,
    /NEW\.stripe_checkout_event_created IS DISTINCT FROM OLD\.stripe_checkout_event_created/,
  );
  assert.match(migration, /v_binding\.last_event_created > p_event_created/);
  assert.match(migration, /last_event_priority/);
  assert.match(migration, /last_event_id/);
  assert.match(migration, /v_outcome IN \('applied', 'superseded'\)/);
  assert.match(migration, /REVOKE ALL.*anon, authenticated/s);
  assert.match(
    migration,
    /REVOKE ALL ON FUNCTION public\.process_stripe_billing_event[\s\S]*FROM PUBLIC, anon, authenticated/,
  );
  assert.match(migration, /GRANT EXECUTE.*TO service_role/s);
});
