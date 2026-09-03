import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

import { verifyMigrationManifest } from "./verify-migrations.mjs";

const repositoryRoot = resolve(import.meta.dirname, "../..");
const projectSupabaseDirectory = join(repositoryRoot, "apps/web/supabase");

async function fixture({ migrations, entries }) {
  const root = await mkdtemp(join(tmpdir(), "phantom-supabase-contract-"));
  const migrationDirectory = join(root, "migrations");
  await mkdir(migrationDirectory);
  await Promise.all(
    Object.entries(migrations).map(([file, contents]) =>
      writeFile(join(migrationDirectory, file), contents),
    ),
  );
  await writeFile(
    join(root, "migration-manifest.json"),
    JSON.stringify({ version: 1, algorithm: "sha256", migrations: entries }),
  );
  return root;
}

test("the committed migration set matches its ordered digest manifest", async () => {
  const result = await verifyMigrationManifest({
    supabaseDirectory: projectSupabaseDirectory,
  });
  assert.equal(result.count, 12);
  assert.equal(result.files[0], "001_initial.sql");
  assert.equal(
    result.files.at(-1),
    "20260903180035_browser_and_service_role_grants.sql",
  );
});

test("advisor hardening preserves RLS identity checks and pins trigger paths", async () => {
  const migration = await readFile(
    join(
      projectSupabaseDirectory,
      "migrations/20260902000000_harden_rls_and_function_paths.sql",
    ),
    "utf8",
  );
  for (const policy of [
    "users_read_own",
    "device_tokens_read_own",
    "team_key_shares_own",
  ]) {
    assert.match(migration, new RegExp(`ALTER POLICY ${policy}`));
  }
  assert.doesNotMatch(migration, /users_update_own/);
  assert.equal(
    [...migration.matchAll(/USING \([^;]*\(SELECT auth\.uid\(\)\)\);/g)].length,
    3,
  );
  assert.match(
    migration,
    /ALTER FUNCTION public\.update_updated_at\(\) SET search_path = pg_catalog;/,
  );
  assert.match(
    migration,
    /ALTER FUNCTION public\.prevent_user_billing_self_update\(\)[\s\S]*SET search_path = pg_catalog;/,
  );
});

test("fails closed when a migration changes without a manifest update", async () => {
  const root = await fixture({
    migrations: { "001_initial.sql": "select 1;\n" },
    entries: [{ file: "001_initial.sql", sha256: "0".repeat(64) }],
  });
  await assert.rejects(
    verifyMigrationManifest({ supabaseDirectory: root }),
    /migration digest mismatch/,
  );
});

test("fails closed when an untracked migration is added", async () => {
  const root = await fixture({
    migrations: {
      "001_initial.sql": "select 1;\n",
      "002_untracked.sql": "select 2;\n",
    },
    entries: [{ file: "001_initial.sql", sha256: "0".repeat(64) }],
  });
  await assert.rejects(
    verifyMigrationManifest({ supabaseDirectory: root }),
    /does not match the SQL migration set/,
  );
});

test("fails closed on duplicate migration versions", async () => {
  const root = await fixture({
    migrations: {
      "001_first.sql": "select 1;\n",
      "001_second.sql": "select 2;\n",
    },
    entries: [
      { file: "001_first.sql", sha256: "0".repeat(64) },
      { file: "001_second.sql", sha256: "0".repeat(64) },
    ],
  });
  await assert.rejects(
    verifyMigrationManifest({ supabaseDirectory: root }),
    /duplicate migration version/,
  );
});

test("fails closed when a SQL migration is a symlink", async () => {
  const root = await fixture({
    migrations: { "source.txt": "select 1;\n" },
    entries: [{ file: "001_initial.sql", sha256: "0".repeat(64) }],
  });
  await symlink("source.txt", join(root, "migrations/001_initial.sql"));
  await assert.rejects(
    verifyMigrationManifest({ supabaseDirectory: root }),
    /migration must be a regular file/,
  );
});

test("workflow remains local-only and supply-chain pinned", async () => {
  const workflow = await readFile(
    join(repositoryRoot, ".github/workflows/ci.yml"),
    "utf8",
  );
  const webJobStart = workflow.indexOf("\n  web:\n");
  const webJobEnd = workflow.indexOf("\n  secret-scan:\n", webJobStart);
  assert.notEqual(webJobStart, -1);
  assert.notEqual(webJobEnd, -1);
  const webJob = workflow.slice(webJobStart, webJobEnd);

  assert.match(webJob, /name: Web security, tests, and build/);
  assert.match(webJob, /actions\/checkout@[a-f0-9]{40}/);
  assert.match(webJob, /actions\/setup-node@[a-f0-9]{40}/);
  assert.match(webJob, /supabase\/setup-cli@[a-f0-9]{40}/);
  assert.match(webJob, /version:\s*2\.116\.0/);
  assert.match(webJob, /supabase db reset --local --no-seed/);
  assert.match(
    webJob,
    /psql --host 127\.0\.0\.1 --port 54322[\s\S]*assert-local-authority\.sql/,
  );
  assert.match(
    webJob,
    /psql --host 127\.0\.0\.1 --port 54322[\s\S]*assert-hosted-grants-preflight\.sql/,
  );
  assert.match(
    webJob,
    /supabase test db --local supabase\/tests\/database/,
  );
  assert.match(
    webJob,
    /supabase db lint --local --level warning --fail-on warning/,
  );
  assert.match(
    webJob,
    /supabase db advisors --local --type all --level warn --fail-on warn/,
  );
  assert.match(webJob, /id: start_database/);
  assert.match(
    webJob,
    /steps\.start_database\.outcome != 'skipped'/,
  );
  assert.doesNotMatch(webJob, /supabase\s+(?:link|db push|migration up)/);
  assert.doesNotMatch(
    webJob,
    /--linked|--project-ref|SUPABASE_ACCESS_TOKEN|SUPABASE_DB_PASSWORD/,
  );
});

test("hosted grant preflight is read-only and fail-closed", async () => {
  const preflight = await readFile(
    join(repositoryRoot, "scripts/supabase/assert-hosted-grants-preflight.sql"),
    "utf8",
  );
  assert.match(preflight, /BEGIN TRANSACTION READ ONLY;/);
  assert.match(preflight, /current_user <> 'postgres'/);
  assert.match(preflight, /owner\.rolname <> 'postgres'/g);
  assert.match(preflight, /relation\.relrowsecurity/);
  assert.match(preflight, /rolname = 'service_role'[\s\S]*rolbypassrls/);
  assert.match(preflight, /defaults\.defaclrole <> 'postgres'::regrole/);
  assert.match(preflight, /ROLLBACK;\s*$/);
  assert.doesNotMatch(preflight, /\b(?:INSERT|UPDATE|DELETE|GRANT|REVOKE|ALTER|CREATE|DROP)\b/);
});

test("runtime authority assertions preserve the hardened user boundary", async () => {
  const assertions = await readFile(
    join(repositoryRoot, "scripts/supabase/assert-local-authority.sql"),
    "utf8",
  );
  assert.match(assertions, /policyname = 'users_update_own'/);
  assert.match(
    assertions,
    /has_table_privilege\('authenticated', 'public\.users', 'UPDATE'\)/,
  );
  assert.match(assertions, /roles = ARRAY\['public'\]::name\[\]/);
  assert.match(assertions, /cmd = 'SELECT'/);
  assert.match(assertions, /permissive = 'PERMISSIVE'/);
  assert.match(assertions, /NOT proc\.prosecdef/);
  assert.match(assertions, /'search_path=pg_catalog' = ANY\(proc\.proconfig\)/);
});

test("local configuration pins Postgres and disables mutable seed inputs", async () => {
  const config = await readFile(
    join(projectSupabaseDirectory, "config.toml"),
    "utf8",
  );
  assert.match(config, /^project_id = "phantom-web-local"$/m);
  assert.match(config, /^major_version = 17$/m);
  assert.match(config, /\[db\.migrations\][\s\S]*?enabled = true/);
  assert.match(config, /\[db\.seed\][\s\S]*?enabled = false/);
  assert.match(config, /\[auth\][\s\S]*?enabled = true/);
  assert.doesNotMatch(
    config,
    /project_ref|access_token|database_password|SUPABASE_/i,
  );
});
