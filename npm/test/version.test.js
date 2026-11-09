// An empty version string must be rejected, never treated as "no version to check".
const assert = require("assert");
const { spawnSync } = require("child_process");
const { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } = require("fs");
const { tmpdir } = require("os");
const { join } = require("path");

const { parseBinaryVersion } = require("../bin/cli.js");

// Binary output: "phantom " with nothing after it is not a version.
for (const empty of ["phantom \n", "phantom \r\n", "phantom ", Buffer.from("phantom \n"), ""]) {
  assert.strictEqual(parseBinaryVersion(empty), null, JSON.stringify(String(empty)));
}

// Package identity: a package.json with version "" must stop the wrapper at load time (nonzero exit).
const fixtureDir = mkdtempSync(join(tmpdir(), "phantom-empty-version-"));
try {
  mkdirSync(join(fixtureDir, "bin"));
  copyFileSync(join(__dirname, "..", "bin", "package-version.js"), join(fixtureDir, "bin", "package-version.js"));
  for (const version of ["", " "]) {
    writeFileSync(join(fixtureDir, "package.json"), JSON.stringify({ name: "phantom-secrets", version }));
    const result = spawnSync(process.execPath, [join(fixtureDir, "bin", "package-version.js")], { encoding: "utf8" });
    assert.notStrictEqual(result.status, 0, `version ${JSON.stringify(version)} must exit nonzero`);
    assert.match(result.stderr, /invalid packaged Phantom version/);
  }
} finally {
  rmSync(fixtureDir, { recursive: true, force: true });
}

console.log("ok: empty version rejected");
