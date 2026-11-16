const assert = require("assert");
const { spawnSync } = require("child_process");
const { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } = require("fs");
const { tmpdir } = require("os");
const { join } = require("path");

const fixture = mkdtempSync(join(tmpdir(), "phantom-version-test-"));
try {
  mkdirSync(join(fixture, "bin"));
  const helper = join(fixture, "bin", "package-version.js");
  copyFileSync(join(__dirname, "../bin/package-version.js"), helper);

  function check(version) {
    writeFileSync(join(fixture, "package.json"), JSON.stringify({ version }));
    const result = spawnSync(process.execPath, [helper], { encoding: "utf8" });
    assert.ifError(result.error);
    return result;
  }

  assert.strictEqual(check("1.2.3").status, 0);
  for (const version of ["1.2", "1..3", ".2.3", "1.2."]) {
    const result = check(version);
    assert.ok(Number.isInteger(result.status) && result.status !== 0, `${version} must exit nonzero`);
    assert.match(result.stderr, /invalid packaged Phantom version/);
  }
} finally {
  rmSync(fixture, { recursive: true, force: true });
}

console.log("npm packaged version rejects missing numeric components");
