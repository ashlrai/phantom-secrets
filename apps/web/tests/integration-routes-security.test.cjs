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
    "Content-Security-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
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

test("identity migration repairs poisoned and victim-colliding profile logins before uniqueness", () => {
  const migration = fs.readFileSync(
    path.join(
      repoDir,
      "supabase/migrations/20260831020000_harden_identity_and_device_auth.sql",
    ),
    "utf8",
  );

  const reconciliation = migration.indexOf(
    "CREATE TEMP TABLE phantom_verified_github_identities",
  );
  const repair = migration.indexOf("UPDATE public.users AS profile");
  const duplicateCheck = migration.indexOf(
    "duplicate normalized GitHub logins must be resolved",
  );
  const uniqueIndex = migration.indexOf(
    "users_github_login_normalized_unique",
  );

  assert.ok(reconciliation >= 0);
  assert.ok(repair > reconciliation);
  assert.ok(duplicateCheck > repair);
  assert.ok(uniqueIndex > duplicateCheck);
  assert.match(migration, /LEFT JOIN auth\.identities AS identity/);
  assert.match(migration, /identity\.provider = 'github'/);
  assert.match(
    migration,
    /SET github_login = identity\.verified_login[\s\S]*identity\.user_id = profile\.id/,
  );
  assert.doesNotMatch(migration, /DELETE FROM public\.users/);
});

test("identity migration quarantines missing, ambiguous, invalid, and duplicate verified identities", () => {
  const migration = fs.readFileSync(
    path.join(
      repoDir,
      "supabase/migrations/20260831020000_harden_identity_and_device_auth.sql",
    ),
    "utf8",
  );

  assert.match(migration, /HAVING count\(identity_id\) <> 1/);
  assert.match(migration, /verified_login !~ '\^\[a-z0-9\]/);
  assert.match(migration, /HAVING count\(DISTINCT user_id\) > 1/);
  assert.match(migration, /BEGIN;[\s\S]*COMMIT;\s*$/);
  assert.match(
    migration,
    /verified login collision\(s\) require operator review/,
  );
  assert.match(migration, /LOCK TABLE auth\.identities IN SHARE MODE/);
  assert.match(migration, /LOCK TABLE public\.users IN ACCESS EXCLUSIVE MODE/);
});

test("identity and device hardening revokes public client privileges", () => {
  const migration = fs.readFileSync(
    path.join(
      repoDir,
      "supabase/migrations/20260831020000_harden_identity_and_device_auth.sql",
    ),
    "utf8",
  );

  assert.match(
    migration,
    /REVOKE UPDATE ON TABLE public\.users FROM PUBLIC, anon, authenticated/,
  );
  assert.match(
    migration,
    /REVOKE ALL ON TABLE public\.device_auth_rate_limits FROM PUBLIC, anon, authenticated/,
  );
  assert.match(
    migration,
    /REVOKE ALL ON FUNCTION[\s\S]*FROM PUBLIC, anon, authenticated/,
  );
  assert.match(migration, /GRANT EXECUTE[\s\S]*TO service_role/);
});

test("team identity is server-owned and device issuance is atomic per client", () => {
  const migration = fs.readFileSync(
    path.join(
      repoDir,
      "supabase/migrations/20260831020000_harden_identity_and_device_auth.sql",
    ),
    "utf8",
  );
  const membersRoute = fs.readFileSync(
    path.join(repoDir, "src/app/api/v1/teams/[team_id]/members/route.ts"),
    "utf8",
  );
  const initiateRoute = fs.readFileSync(
    path.join(repoDir, "src/app/api/v1/auth/device/initiate/route.ts"),
    "utf8",
  );
  const authLibrary = fs.readFileSync(
    path.join(repoDir, "src/lib/auth.ts"),
    "utf8",
  );
  const approveRoute = fs.readFileSync(
    path.join(repoDir, "src/app/api/v1/auth/device/approve/route.ts"),
    "utf8",
  );

  assert.match(migration, /DROP POLICY IF EXISTS "users_update_own"/);
  assert.match(
    migration,
    /REVOKE UPDATE ON TABLE public\.users FROM PUBLIC, anon, authenticated/,
  );
  assert.match(migration, /github_login_normalized text[\s\S]*GENERATED ALWAYS/);
  assert.match(migration, /UNIQUE INDEX[\s\S]*github_login_normalized/i);
  assert.match(membersRoute, /\.eq\("github_login_normalized", normalizedLogin\)/);
  assert.doesNotMatch(membersRoute, /\.ilike\("github_login"/);

  assert.match(migration, /CREATE OR REPLACE FUNCTION public\.issue_device_code/);
  assert.match(migration, /SECURITY DEFINER/);
  assert.match(migration, /SET search_path = pg_catalog/);
  assert.match(migration, /ON CONFLICT \(key_hash\) DO UPDATE/g);
  assert.match(migration, /FOR UPDATE SKIP LOCKED/);
  assert.match(
    migration,
    /REVOKE ALL ON FUNCTION[\s\S]*FROM PUBLIC, anon, authenticated/,
  );
  assert.match(migration, /GRANT EXECUTE[\s\S]*TO service_role/);
  assert.match(initiateRoute, /x-vercel-forwarded-for/);
  assert.match(initiateRoute, /\.rpc\("issue_device_code"/);
  assert.doesNotMatch(initiateRoute, /\.from\("device_tokens"\)/);
  assert.match(initiateRoute, /cache-control", "no-store"/);

  assert.match(authLibrary, /identity\.provider === "github"/);
  assert.doesNotMatch(authLibrary, /user\.user_metadata/);
  assert.match(approveRoute, /verifiedGithubLoginForUser\(user\)/);
  assert.doesNotMatch(approveRoute, /user\.user_metadata/);
});

test("device and analytics URLs do not persist or report query-bearing values", () => {
  const devicePage = fs.readFileSync(
    path.join(repoDir, "src/app/device/device-authorization-client.tsx"),
    "utf8",
  );
  const posthogConfig = fs.readFileSync(
    path.join(repoDir, "src/lib/posthog.ts"),
    "utf8",
  );
  const providers = fs.readFileSync(
    path.join(repoDir, "src/app/providers.tsx"),
    "utf8",
  );

  assert.match(devicePage, /sessionStorage\.setItem\("phantom_device_code"/);
  assert.doesNotMatch(devicePage, /localStorage/);
  assert.doesNotMatch(devicePage, /redirectTo:[^\n]*code=/);
  assert.match(posthogConfig, /capture_pageview:\s*false/);
  assert.match(posthogConfig, /capture_pageleave:\s*false/);
  assert.match(posthogConfig, /autocapture:\s*false/);
  assert.match(posthogConfig, /capture_performance:\s*false/);
  assert.match(posthogConfig, /disable_capture_url_hashes:\s*true/);
  assert.match(posthogConfig, /disable_persistence:\s*true/);
  assert.match(posthogConfig, /disable_session_recording:\s*true/);
  assert.match(posthogConfig, /save_campaign_params:\s*false/);
  assert.match(posthogConfig, /save_referrer:\s*false/);
  assert.match(posthogConfig, /advanced_disable_flags:\s*true/);
  assert.match(posthogConfig, /before_send:/);
  assert.match(
    posthogConfig,
    /\$current_url:\s*canonicalBrowserUrl\(\)/g,
  );
  assert.match(posthogConfig, /\$pathname:\s*window\.location\.pathname/g);
  assert.match(providers, /\$current_url:\s*`\$\{window\.location\.origin\}\$\{pathname\}`/);
});
