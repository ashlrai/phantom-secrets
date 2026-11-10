import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";

import { verifyMigrationManifest } from "./verify-migrations.mjs";

const repositoryRoot = resolve(import.meta.dirname, "../..");
const projectSupabaseDirectory = join(repositoryRoot, "apps/web/supabase");

async function fixture({ migrations, entries, directory }) {
  const root = await mkdtemp(join(tmpdir(), "phantom-supabase-contract-"));
  const base = directory ? join(root, directory) : root;
  const migrationDirectory = join(base, "migrations");
  await mkdir(migrationDirectory, { recursive: true });
  for (const [file, contents] of Object.entries(migrations)) {
    await writeFile(join(migrationDirectory, file), contents);
  }
  await writeFile(
    join(base, "migration-manifest.json"),
    JSON.stringify({ version: 1, algorithm: "sha256", migrations: entries }),
  );
  return base;
}

test("verifies valid migrations created in reverse filename order", async () => {
  const migrations = {
    "003_third.sql": "select 3;\n",
    "002_second.sql": "select 2;\n",
    "001_first.sql": "select 1;\n",
  };
  const entries = Object.entries(migrations)
    .sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
    .map(([file, contents]) => ({
      file,
      sha256: createHash("sha256").update(contents).digest("hex"),
    }));
  const root = await fixture({ migrations, entries });
  const result = await verifyMigrationManifest({ supabaseDirectory: root });
  assert.deepEqual(result, {
    count: 3,
    files: ["001_first.sql", "002_second.sql", "003_third.sql"],
  });

  // Force reverse enumeration even on filesystems that return sorted entries.
  const preload = `
    import fs from "node:fs";
    import { syncBuiltinESMExports } from "node:module";
    const original = fs.promises.readdir;
    fs.promises.readdir = async (...args) => {
      const entries = await original(...args);
      return entries.sort((a, b) => a.name < b.name ? 1 : a.name > b.name ? -1 : 0);
    };
    syncBuiltinESMExports();
  `;
  const resultWithReverseEnumeration = spawnSync(
    process.execPath,
    ["--import", `data:text/javascript,${encodeURIComponent(preload)}`,
      join(import.meta.dirname, "verify-migrations.mjs"), root],
    { encoding: "utf8" },
  );
  assert.ifError(resultWithReverseEnumeration.error);
  assert.equal(resultWithReverseEnumeration.status, 0, resultWithReverseEnumeration.stderr);
  assert.match(resultWithReverseEnumeration.stdout, /Verified 3 ordered Supabase migration digests\./);
});

test("the column-revoke follow-up covers platform_tokens and oauth_states", async () => {
  const migration = await readFile(
    join(
      projectSupabaseDirectory,
      "migrations/20261110053000_revoke_platform_token_oauth_state_columns.sql",
    ),
    "utf8",
  );
  assert.match(migration, /REVOKE ALL PRIVILEGES ON TABLE public\.oauth_states/);
  assert.match(migration, /ARRAY\['platform_tokens', 'oauth_states'\]/);
  assert.match(
    migration,
    /REVOKE %s \(%s\) ON TABLE %s FROM PUBLIC, anon, authenticated, service_role/,
  );
  assert.match(
    migration,
    /REVOKE ALL PRIVILEGES ON TABLE public\.oauth_states\s+FROM PUBLIC, anon, authenticated;/,
  );
});

test("the committed migration set matches its ordered digest manifest", async () => {
  const result = await verifyMigrationManifest({
    supabaseDirectory: projectSupabaseDirectory,
  });
  assert.equal(result.count, 15);
  assert.equal(result.files[0], "001_initial.sql");
  assert.equal(
    result.files.at(-1),
    "20261110053000_revoke_platform_token_oauth_state_columns.sql",
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
    /duplicate migration version: 001 \(001_first\.sql, 001_second\.sql\)/,
  );
});

test("names the conflicting version when the duplicate is not the first migration", async () => {
  const sha256 = "0".repeat(64);
  const root = await fixture({
    migrations: {
      "001_initial.sql": "select 1;\n",
      "20260902000000_alpha.sql": "select 2;\n",
      "20260902000000_beta.sql": "select 3;\n",
      "20260903000000_gamma.sql": "select 4;\n",
    },
    entries: [
      { file: "001_initial.sql", sha256 },
      { file: "20260902000000_alpha.sql", sha256 },
      { file: "20260902000000_beta.sql", sha256 },
      { file: "20260903000000_gamma.sql", sha256 },
    ],
  });
  await assert.rejects(
    verifyMigrationManifest({ supabaseDirectory: root }),
    (error) => {
      assert.match(
        error.message,
        /duplicate migration version: 20260902000000 \(20260902000000_alpha\.sql, 20260902000000_beta\.sql\)/,
      );
      assert.doesNotMatch(error.message, /version: 001/);
      return true;
    },
  );
});

test("rejects a duplicate version even when every digest is correct", async () => {
  const first = "select 1;\n";
  const second = "select 2;\n";
  const digest = (text) => createHash("sha256").update(text).digest("hex");
  const root = await fixture({
    migrations: { "007_a.sql": first, "007_b.sql": second },
    entries: [
      { file: "007_a.sql", sha256: digest(first) },
      { file: "007_b.sql", sha256: digest(second) },
    ],
  });
  await assert.rejects(
    verifyMigrationManifest({ supabaseDirectory: root }),
    /duplicate migration version: 007 /,
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

test("reports the first non-regular SQL entry in filename order", async () => {
  const root = await fixture({ migrations: {}, entries: [] });
  await symlink("missing", join(root, "migrations/002_second.sql"));
  await symlink("missing", join(root, "migrations/001_first.sql"));
  await assert.rejects(
    verifyMigrationManifest({ supabaseDirectory: root }),
    /migration must be a regular file: 001_first\.sql/,
  );
});

test("fails closed on an empty migration directory with an empty manifest", async () => {
  const root = await fixture({ migrations: {}, entries: [] });
  await assert.rejects(
    verifyMigrationManifest({ supabaseDirectory: root }),
    /migration manifest must contain at least one migration/,
  );
});

test("fails closed when the manifest lists migrations but the directory is empty", async () => {
  const root = await fixture({
    migrations: {},
    entries: [{ file: "001_initial.sql", sha256: "0".repeat(64) }],
  });
  await assert.rejects(
    verifyMigrationManifest({ supabaseDirectory: root }),
    /does not match the SQL migration set\nmanifest: 001_initial\.sql\nfiles: $/,
  );
});

test("ignores non-SQL files so a directory holding only notes counts as empty", async () => {
  const root = await fixture({
    migrations: { "README.md": "notes\n" },
    entries: [],
  });
  await assert.rejects(
    verifyMigrationManifest({ supabaseDirectory: root }),
    /migration manifest must contain at least one migration/,
  );
});

test("ignores unrelated files alongside valid migrations", async () => {
  const sql = "select 1;\n";
  const sha256 = createHash("sha256").update(sql).digest("hex");
  const root = await fixture({
    migrations: {
      "001_initial.sql": sql,
      "README.md": "# scratch notes\n",
      ".DS_Store": "",
      "001_initial.sql.bak": sql,
      "DRAFT.SQL": "select 2;\n",
    },
    entries: [{ file: "001_initial.sql", sha256 }],
  });
  const result = await verifyMigrationManifest({ supabaseDirectory: root });
  assert.equal(result.count, 1);
  assert.deepEqual(result.files, ["001_initial.sql"]);
});

test("ignores non-regular entries that are not SQL migrations", async () => {
  const sql = "select 1;\n";
  const sha256 = createHash("sha256").update(sql).digest("hex");
  const root = await fixture({
    migrations: { "001_initial.sql": sql },
    entries: [{ file: "001_initial.sql", sha256 }],
  });
  await symlink("missing-target", join(root, "migrations/notes.txt"));
  await mkdir(join(root, "migrations/attic"));
  const result = await verifyMigrationManifest({ supabaseDirectory: root });
  assert.equal(result.count, 1);
  assert.deepEqual(result.files, ["001_initial.sql"]);
});

test("reads the spaced fixture directory instead of an unspaced sibling", async () => {
  const sql = "select 1;\n";
  const sha256 = createHash("sha256").update(sql).digest("hex");
  const supabaseDirectory = await fixture({
    directory: "supabase with spaces",
    migrations: { "001_initial.sql": sql },
    entries: [{ file: "001_initial.sql", sha256 }],
  });
  assert.ok(supabaseDirectory.includes(" "));

  // A sibling decoy proves the spaced directory, not the temp root, is read.
  const decoySql = "select 9;\n";
  const decoyRoot = dirname(supabaseDirectory);
  await mkdir(join(decoyRoot, "migrations"));
  await writeFile(join(decoyRoot, "migrations/999_decoy.sql"), decoySql);
  await writeFile(
    join(decoyRoot, "migration-manifest.json"),
    JSON.stringify({
      version: 1,
      algorithm: "sha256",
      migrations: [
        {
          file: "999_decoy.sql",
          sha256: createHash("sha256").update(decoySql).digest("hex"),
        },
      ],
    }),
  );

  const result = await verifyMigrationManifest({ supabaseDirectory });
  assert.equal(result.count, 1);
  assert.deepEqual(result.files, ["001_initial.sql"]);
});

test("the CLI verifies a supabase directory whose path contains spaces", async () => {
  const sql = "select 1;\n";
  const sha256 = createHash("sha256").update(sql).digest("hex");
  const supabaseDirectory = await fixture({
    directory: "supabase with spaces",
    migrations: { "001_initial.sql": sql },
    entries: [{ file: "001_initial.sql", sha256 }],
  });
  const result = spawnSync(
    process.execPath,
    [join(import.meta.dirname, "verify-migrations.mjs"), supabaseDirectory],
    { encoding: "utf8" },
  );
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Verified 1 ordered Supabase migration digests\./);
});

test("fails closed and names the directory when the migrations directory is missing", async () => {
  const root = await mkdtemp(join(tmpdir(), "phantom-supabase-contract-"));
  await writeFile(
    join(root, "migration-manifest.json"),
    JSON.stringify({
      version: 1,
      algorithm: "sha256",
      migrations: [{ file: "001_initial.sql", sha256: "0".repeat(64) }],
    }),
  );
  const missing = join(root, "migrations");
  await assert.rejects(
    verifyMigrationManifest({ supabaseDirectory: root }),
    (error) => {
      assert.equal(error.message, `migration directory not found: ${missing}`);
      return true;
    },
  );
});

test("the CLI exits nonzero and names the missing migrations directory", async () => {
  const root = await mkdtemp(join(tmpdir(), "phantom-supabase-contract-"));
  const result = spawnSync(
    process.execPath,
    [join(import.meta.dirname, "verify-migrations.mjs"), root],
    { encoding: "utf8" },
  );
  assert.ifError(result.error);
  assert.notEqual(result.status, 0);
  assert.equal(result.stdout, "");
  assert.ok(
    result.stderr.includes(`migration directory not found: ${join(root, "migrations")}`),
    result.stderr,
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
  assert.match(assertions, /platform_tokens must not retain a plaintext access_token column/);
  assert.match(assertions, /relation\.relname IN \('oauth_states', 'platform_tokens'\)/);
  assert.match(assertions, /tablename IN \('oauth_states', 'platform_tokens'\)/);
  assert.match(assertions, /ARRAY\['SELECT', 'INSERT', 'UPDATE', 'DELETE'\]/);
  assert.match(assertions, /service role OAuth table grants are incomplete/);
  assert.match(assertions, /consume_vercel_oauth_state\(bytea, uuid\)/);
  assert.match(assertions, /issue_vercel_oauth_state\(bytea, uuid\)/);
  assert.match(assertions, /public clients must not execute OAuth state consumption/);
  assert.match(
    assertions,
    /public clients must not retain column privileges on OAuth state or platform tokens/,
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
