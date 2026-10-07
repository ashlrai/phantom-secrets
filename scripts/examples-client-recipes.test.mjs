import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const suffix = process.platform === "win32" ? ".exe" : "";
const built = join(root, "target", "debug", `phantom${suffix}`);
const recipes = ["claude-code", "cursor", "github-actions"];

function recipe(name, phantom) {
  return spawnSync(process.execPath, [join(root, "examples", name, "run.mjs"), "--phantom", phantom], {
    encoding: "utf8", timeout: 120_000, maxBuffer: 1024 * 1024,
  });
}

for (const name of recipes) {
  test(`${name} recipe passes against the workspace build`, { skip: !existsSync(built) && "target/debug/phantom not built" }, () => {
    const result = recipe(name, built);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.match(result.stdout, /^COMPLETE: /m);
    assert.doesNotMatch(result.stdout, /^FAIL /m);
  });

  test(`${name} recipe reports a missing binary as incomplete, never passed`, () => {
    const result = recipe(name, join(tmpdir(), `missing-phantom-${process.pid}${suffix}`));
    assert.equal(result.status, 2, result.stdout + result.stderr);
    assert.match(result.stdout, /^INCOMPLETE: /m);
    assert.doesNotMatch(result.stdout, /^COMPLETE: /m);
  });
}

test("recipes fail when a runtime leaves the real value in .env", { skip: process.platform === "win32" && "script fixtures are Unix-only" }, () => {
  const dir = mkdtempSync(join(tmpdir(), "phantom-recipe-fake-"));
  try {
    // A fake `phantom` that "succeeds" at everything but protects nothing.
    const fake = join(dir, "phantom");
    writeFileSync(fake, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
    for (const name of ["claude-code", "cursor"]) {
      const result = recipe(name, fake);
      assert.equal(result.status, 1, `${name}: ${result.stdout}${result.stderr}`);
      assert.match(result.stdout, /^FAIL \.env still holds the real value/m);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("recipes reject relative binary paths", () => {
  const result = spawnSync(process.execPath, [join(root, "examples", "cursor", "run.mjs"), "--phantom", "phantom"], { encoding: "utf8" });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Usage:/);
});
