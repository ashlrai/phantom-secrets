const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const repoDir = path.resolve(__dirname, "..");

function loadRoute(relativePath) {
  const routePath = path.join(repoDir, relativePath);
  const source = fs.readFileSync(routePath, "utf8");
  const output = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
    },
    fileName: routePath,
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
  fn(module.exports, require, module, routePath, path.dirname(routePath));
  return { route: module.exports, source };
}

for (const [name, routePath] of [
  ["install", "src/app/api/v1/integrations/vercel/install/route.ts"],
  ["callback", "src/app/api/v1/integrations/vercel/callback/route.ts"],
]) {
  test(`Vercel ${name} route fails closed without external side effects`, async () => {
    const { route, source } = loadRoute(routePath);
    const response = await route.GET(
      new Request(
        `https://phm.dev/api/v1/integrations/vercel/${name}?code=attacker&state=attacker`,
      ),
    );

    assert.equal(response.status, 503);
    assert.equal(response.headers.get("cache-control"), "no-store");
    const body = await response.json();
    assert.equal(body.error, "integration_disabled");
    assert.equal(typeof body.message, "string");
    assert.ok(body.message.length > 20);
    assert.doesNotMatch(source, /access_token|platform_tokens|fetch\s*\(/);
  });
}

test("the web application defines baseline response security headers", () => {
  const config = fs.readFileSync(path.join(repoDir, "next.config.ts"), "utf8");

  for (const expected of [
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
  ]) {
    assert.match(config, new RegExp(`key:\\s*["']${expected}["']`));
  }

  assert.match(config, /source:\s*["']\/:path\*["']/);
  assert.match(config, /poweredByHeader:\s*false/);
});

test("billing-field trigger distinguishes authenticated and service database roles", () => {
  const historicalMigration = fs.readFileSync(
    path.join(
      repoDir,
      "supabase/migrations/20260523043035_harden_auth_and_rls.sql",
    ),
    "utf8",
  );
  const forwardMigration = fs.readFileSync(
    path.join(
      repoDir,
      "supabase/migrations/20260831010000_stripe_event_processing_state.sql",
    ),
    "utf8",
  );

  assert.match(historicalMigration, /auth\.role\s*\(\)/);
  assert.match(forwardMigration, /current_user\s*=\s*'authenticated'/);
  assert.doesNotMatch(forwardMigration, /auth\.role\s*\(/);
  assert.match(forwardMigration, /prevent_user_billing_self_update/);
});
