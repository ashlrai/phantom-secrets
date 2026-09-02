#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const MIGRATION_NAME = /^(?<version>[0-9]+)_[a-z0-9][a-z0-9_]*\.sql$/;
const SHA256 = /^[a-f0-9]{64}$/;

export async function verifyMigrationManifest({
  supabaseDirectory,
  manifestPath = join(supabaseDirectory, "migration-manifest.json"),
} = {}) {
  if (!supabaseDirectory) {
    throw new Error("supabaseDirectory is required");
  }

  const migrationDirectory = join(supabaseDirectory, "migrations");
  const migrationEntries = (await readdir(migrationDirectory, { withFileTypes: true }))
    .filter((entry) => entry.name.endsWith(".sql"));
  const nonRegularMigration = migrationEntries.find((entry) => !entry.isFile());
  if (nonRegularMigration) {
    throw new Error(
      `migration must be a regular file: ${nonRegularMigration.name}`,
    );
  }
  const migrationFiles = migrationEntries
    .map((entry) => entry.name)
    .sort();
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));

  if (manifest.version !== 1 || manifest.algorithm !== "sha256") {
    throw new Error("migration manifest must use version 1 and sha256");
  }
  if (!Array.isArray(manifest.migrations) || manifest.migrations.length === 0) {
    throw new Error("migration manifest must contain at least one migration");
  }

  const manifestFiles = manifest.migrations.map(({ file }) => file);
  if (new Set(manifestFiles).size !== manifestFiles.length) {
    throw new Error("migration manifest contains duplicate file entries");
  }
  if (
    JSON.stringify(manifestFiles) !==
    JSON.stringify([...manifestFiles].sort())
  ) {
    throw new Error("migration manifest entries must be lexically ordered");
  }
  if (JSON.stringify(manifestFiles) !== JSON.stringify(migrationFiles)) {
    throw new Error(
      `migration manifest does not match the SQL migration set\nmanifest: ${manifestFiles.join(", ")}\nfiles: ${migrationFiles.join(", ")}`,
    );
  }

  const versions = new Set();
  for (const entry of manifest.migrations) {
    const match = MIGRATION_NAME.exec(entry.file);
    if (!match) {
      throw new Error(`invalid imperative migration filename: ${entry.file}`);
    }
    if (versions.has(match.groups.version)) {
      throw new Error(`duplicate migration version: ${match.groups.version}`);
    }
    versions.add(match.groups.version);

    if (!SHA256.test(entry.sha256)) {
      throw new Error(`invalid sha256 for ${entry.file}`);
    }
  }

  for (const entry of manifest.migrations) {
    const contents = await readFile(join(migrationDirectory, entry.file));
    const actual = createHash("sha256").update(contents).digest("hex");
    if (actual !== entry.sha256) {
      throw new Error(
        `migration digest mismatch for ${entry.file}: expected ${entry.sha256}, got ${actual}`,
      );
    }
  }

  return { count: manifest.migrations.length, files: manifestFiles };
}

async function main() {
  const scriptDirectory = dirname(fileURLToPath(import.meta.url));
  const repositoryRoot = resolve(scriptDirectory, "../..");
  const supabaseDirectory = resolve(
    process.argv[2] ?? join(repositoryRoot, "apps/web/supabase"),
  );
  const result = await verifyMigrationManifest({ supabaseDirectory });
  process.stdout.write(
    `Verified ${result.count} ordered Supabase migration digests.\n`,
  );
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
