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
  assert.equal(result.count, 10);
  assert.equal(result.files[0], "001_initial.sql");
  assert.equal(
    result.files.at(-1),
    "20260831020000_harden_identity_and_device_auth.sql",
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
