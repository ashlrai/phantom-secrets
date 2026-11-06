const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const repoDir = path.resolve(__dirname, "../../..");
const readRepo = (file) => fs.readFileSync(path.join(repoDir, file), "utf8");

test("generated public install guidance retains the verified release while source advances", () => {
  const readme = readRepo("README.md");
  assert.match(readme, /verified_GitHub_release-v0\.7\.9/);
  assert.match(readme, /source_version-v0\.8\.3/);
  assert.match(readme, /CHANGELOG\.md#083---2026-11-06/);

  for (const file of ["README.md", "docs/getting-started.md"]) {
    const source = readRepo(file);
    assert.equal(
      source.match(/releases\/download\/v0\.7\.9\/phantom-(?:aarch64|x86_64)-(?:apple-darwin|unknown-linux-gnu|pc-windows-msvc)\.(?:tar\.gz|zip)\)/g)?.length,
      6,
      `${file} must retain all six verified public archive links`,
    );
    assert.doesNotMatch(source, /releases\/(?:tag|download)\/v0\.8\.[0-9]+/,
      `${file} must not describe a source candidate as a published release`);
  }

  const gettingStarted = readRepo("docs/getting-started.md");
  const verifyBlock = gettingStarted.split("<!-- fresh:begin docs-verify-version-output -->")[1]
    ?.split("<!-- fresh:end -->")[0];
  assert.ok(verifyBlock, "missing public version verification block");
  assert.match(verifyBlock, /# phantom 0\.7\.9/);
  assert.match(verifyBlock, /# phantom-mcp 0\.7\.9/);
  assert.doesNotMatch(verifyBlock, /0\.8\.[0-9]+/);

  const recipe = readRepo("examples/github-actions/README.md");
  assert.match(recipe, /v0\.7\.9 release/);
  assert.doesNotMatch(recipe, /v0\.8\.[0-9]+ release/);
  assert.match(readRepo("ROADMAP.md"), /0\.8\.0[^\n]+: staged/);
});

