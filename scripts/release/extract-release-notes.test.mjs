import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const extractor = join(repoRoot, "scripts", "release", "extract-release-notes.mjs");

function workspaceVersion() {
  const cargoToml = readFileSync(join(repoRoot, "Cargo.toml"), "utf8");
  const match = cargoToml.match(
    /\[workspace\.package\][\s\S]*?^version\s*=\s*"([^"]+)"/m,
  );
  assert.ok(match, "workspace version must be readable");
  return match[1];
}

test("current workspace version release notes include the complete candidate tranche", () => {
  const version = workspaceVersion();
  const result = spawnSync(process.execPath, [extractor, `v${version}`], {
    cwd: repoRoot,
    encoding: "utf8",
  });

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, new RegExp(`^## \\[${version.replaceAll(".", "\\.")}\\]`, "m"));
  assert.match(result.stdout, /^### Breaking changes and migration$/m);
  assert.match(result.stdout, /metadata-only `phantom status --json`/);
  assert.match(result.stdout, /without opening the vault, using a bearer/);
  assert.match(result.stdout, /Claude project MCP registration to `.mcp.json`/);
  assert.match(result.stdout, /legacy-only registration/);
  assert.match(result.stdout, /cross-platform CI matrix/);
  assert.doesNotMatch(result.stdout, /^## \\[Unreleased\\]$/m);
  assert.match(result.stdout, /Existing `v0\.7\.8` artifacts stay immutable/);
});

test("missing release notes fail closed", () => {
  const result = spawnSync(process.execPath, [extractor, "v999.999.999"], {
    cwd: repoRoot,
    encoding: "utf8",
  });

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /has no ## \[999\.999\.999\] section/);
});
