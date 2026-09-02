#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  copyFileSync,
  cpSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const exampleRoot = join(repoRoot, "examples", "first-five-minutes");
const fixtureRoot = join(repoRoot, "scripts", "fixtures", "first-five-minutes");
const runner = join(exampleRoot, "run.mjs");
const expected = readFileSync(join(exampleRoot, "expected-output.txt"), "utf8").replace(/\r\n/gu, "\n");

function runCopiedExample({ environmentFixture, policyFixture } = {}) {
  const sandbox = mkdtempSync(join(tmpdir(), "phantom-first-five-minutes-regression-"));
  const copiedExample = join(sandbox, "example");
  cpSync(exampleRoot, copiedExample, { recursive: true });
  if (environmentFixture) {
    copyFileSync(join(fixtureRoot, environmentFixture), join(copiedExample, ".env.example"));
  }
  if (policyFixture) {
    copyFileSync(join(fixtureRoot, policyFixture), join(copiedExample, "policy.json"));
  }

  const result = spawnSync(process.execPath, [join(copiedExample, "run.mjs")], {
    cwd: sandbox,
    encoding: "utf8",
    env: {
      PATH: process.env.PATH ?? "",
      SystemRoot: process.env.SystemRoot ?? "",
    },
  });
  rmSync(sandbox, { recursive: true, force: true });
  return result;
}

test("first-five-minutes walkthrough is deterministic and leaves no local state", () => {
  const emptyWorkingDirectory = mkdtempSync(join(tmpdir(), "phantom-first-five-minutes-"));
  try {
    const result = spawnSync(process.execPath, [runner], {
      cwd: emptyWorkingDirectory,
      encoding: "utf8",
      env: {
        PATH: process.env.PATH ?? "",
        SystemRoot: process.env.SystemRoot ?? "",
      },
    });

    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stderr, "");
    assert.equal(result.stdout, expected);
    assert.deepEqual(readdirSync(emptyWorkingDirectory), []);
  } finally {
    rmSync(emptyWorkingDirectory, { recursive: true, force: true });
  }
});

test("first-five-minutes fixtures contain no credential or persistent token mapping", () => {
  const environment = readFileSync(join(exampleRoot, ".env.example"), "utf8");
  const policy = readFileSync(join(exampleRoot, "policy.json"), "utf8");

  assert.match(environment, /^BILLING_API_TOKEN=<enter-in-trusted-terminal>$/m);
  assert.match(environment, /^PUBLIC_API_BASE=https:\/\/api\.example\.invalid$/m);
  assert.doesNotMatch(environment, /(?:^|\W)phm_[A-Za-z0-9_-]+/u);
  assert.doesNotMatch(policy, /(?:^|\W)phm_[A-Za-z0-9_-]+/u);
  assert.deepEqual(JSON.parse(policy).secret_names, ["BILLING_API_TOKEN"]);
});

test("first-five-minutes rejects a plaintext duplicate before an approved placeholder", () => {
  const result = runCopiedExample({ environmentFixture: "duplicate-secret.env" });

  assert.notEqual(result.status, 0);
  assert.equal(result.stdout, "");
  assert.equal(result.stderr, "ERROR duplicate environment key: BILLING_API_TOKEN\n");
});

test("first-five-minutes rejects environment and policy schema expansion", async (context) => {
  await context.test("extra environment key", () => {
    const result = runCopiedExample({ environmentFixture: "extra-env-key.env" });
    assert.notEqual(result.status, 0);
    assert.equal(result.stderr, "ERROR the example environment schema changed\n");
  });

  await context.test("extra policy key", () => {
    const result = runCopiedExample({ policyFixture: "extra-policy-key.json" });
    assert.notEqual(result.status, 0);
    assert.equal(result.stderr, "ERROR the policy schema changed\n");
  });
});

test("first-five-minutes rejects duplicate policy keys before trusting parsed values", () => {
  const result = runCopiedExample({ policyFixture: "duplicate-policy-key.json" });

  assert.notEqual(result.status, 0);
  assert.equal(result.stdout, "");
  assert.equal(result.stderr, "ERROR the policy must use canonical unique-key JSON\n");
});

test("first-five-minutes runner remains read-only, local-only, and subprocess-free", () => {
  const source = readFileSync(runner, "utf8");
  const imports = source.match(/^import .+;$/gmu) ?? [];

  assert.deepEqual(imports, [
    'import { readFileSync } from "node:fs";',
    'import { dirname, join } from "node:path";',
    'import { fileURLToPath } from "node:url";',
  ]);

  let sourceWithoutAllowedImports = source;
  for (const allowedImport of imports) {
    sourceWithoutAllowedImports = sourceWithoutAllowedImports.replace(allowedImport, "");
  }
  assert.doesNotMatch(
    sourceWithoutAllowedImports,
    /^\s*import(?!\s*\.)/gmu,
    "unreviewed static, side-effect, or multiline import"
  );

  const deniedEscapeHatches = [
    ["dynamic import", /\bimport\s*\(/u],
    ["re-export module loading", /^\s*export\b/gmu],
    ["CommonJS require", /\brequire\s*\(/u],
    ["built-in module lookup", /\bgetBuiltinModule\s*\(/u],
    ["native module binding", /\b(?:_linkedBinding|binding|dlopen)\s*\(/u],
    ["filesystem promises", /(?:node:fs\/promises|\bfs\.promises\b)/u],
    [
      "filesystem write API",
      /\b(?:appendFile|appendFileSync|chmod|chmodSync|chown|chownSync|copyFile|copyFileSync|cp|cpSync|createWriteStream|link|linkSync|lutimes|lutimesSync|mkdir|mkdirSync|mkdtemp|mkdtempSync|open|openSync|rename|renameSync|rm|rmSync|rmdir|rmdirSync|symlink|symlinkSync|truncate|truncateSync|unlink|unlinkSync|utimes|utimesSync|writeFile|writeFileSync|writev|writevSync)\s*\(/u,
    ],
    ["global network API", /\b(?:EventSource|WebSocket|WebTransport|XMLHttpRequest|fetch)\b/u],
    ["beacon network API", /\bsendBeacon\s*\(/u],
  ];

  for (const [name, pattern] of deniedEscapeHatches) {
    assert.doesNotMatch(source, pattern, name);
  }
});
