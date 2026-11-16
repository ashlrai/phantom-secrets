// A version missing a numeric component (1.2, 1.2., 1..3) must never be accepted
// as release identity: the output parser returns null and the package loader exits nonzero.
const assert = require("assert");
const { spawnSync } = require("child_process");
const { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } = require("fs");
const { tmpdir } = require("os");
const { join } = require("path");

const { parseBinaryVersion } = require("../bin/cli.js");

const malformedVersions = ["1.2", "1.2.", "1..3", ".1.2", "1.2.x", "1"];

for (const version of malformedVersions) {
  assert.strictEqual(parseBinaryVersion(`phantom-mcp ${version}\n`), null, version);
}

const fixtureDir = mkdtempSync(join(tmpdir(), "phantom-mcp-version-test-"));
try {
  mkdirSync(join(fixtureDir, "bin"));
  copyFileSync(join(__dirname, "..", "bin", "package-version.js"), join(fixtureDir, "bin", "package-version.js"));

  for (const version of [...malformedVersions, "1.2.3"]) {
    writeFileSync(join(fixtureDir, "package.json"), JSON.stringify({ version }));
    const result = spawnSync(process.execPath, ["-e", 'require("./bin/package-version.js")'], {
      cwd: fixtureDir,
      encoding: "utf8",
    });
    if (version === "1.2.3") {
      assert.strictEqual(result.status, 0, "control: well-formed version must load");
    } else {
      assert.notStrictEqual(result.status, 0, `${version} must exit nonzero`);
      assert.match(result.stderr, /invalid packaged Phantom version/, version);
    }
  }
} finally {
  rmSync(fixtureDir, { recursive: true, force: true });
}

console.log("npm MCP wrapper rejects versions with a missing numeric component");
