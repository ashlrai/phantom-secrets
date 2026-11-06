const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { pathToFileURL } = require("node:url");

const repoDir = path.resolve(__dirname, "../../..");
const readRepo = (file) => fs.readFileSync(path.join(repoDir, file), "utf8");

function assertSourceGuidance(readme, source) {
  assert.match(readme, /verified_GitHub_release-v0\.7\.9/);
  const badges = readme.match(/source_version-v[^-\s)]+/g) || [];
  assert.deepEqual(badges, [`source_version-${source.tag}`]);
  const links = readme.match(/CHANGELOG\.md#[a-z0-9-]+/g) || [];
  assert.deepEqual(links, [`CHANGELOG.md#${source.release.anchor}`]);
}

async function sourceMetadata() {
  const { loadSources } = await import(pathToFileURL(path.join(repoDir, "scripts/freshness/sources.mjs")).href);
  return loadSources(repoDir);
}

test("source guidance rejects stale, missing and duplicate candidate metadata", async () => {
  const source = await sourceMetadata();
  const readme = readRepo("README.md");
  assertSourceGuidance(readme, source);
  for (const marker of [`source_version-${source.tag}`, `CHANGELOG.md#${source.release.anchor}`]) {
    for (const mutant of [readme.replace(marker, "stale"), readme + `\n${marker}`]) {
      assert.throws(() => assertSourceGuidance(mutant, source));
    }
  }
  const future = { tag: "v99.98.97", release: { anchor: "999897---2099-01-01" } };
  const futureReadme = readme.replace(`source_version-${source.tag}`, `source_version-${future.tag}`)
    .replace(`CHANGELOG.md#${source.release.anchor}`, `CHANGELOG.md#${future.release.anchor}`);
  assertSourceGuidance(futureReadme, future);
  assert.throws(() => assertSourceGuidance(futureReadme.replace("verified_GitHub_release-v0.7.9", "verified_GitHub_release-v99.98.97"), future));
});

test("generated public install guidance retains the verified release while source advances", async () => {
  assertSourceGuidance(readRepo("README.md"), await sourceMetadata());

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

