const assert = require("assert");
const { readFileSync } = require("fs");
const { join, resolve } = require("path");

const repoRoot = resolve(__dirname, "..", "..");
const phantomCli = require(join(repoRoot, "npm", "bin", "cli.js"));
const phantomMcp = require(join(repoRoot, "npm-mcp", "bin", "cli.js"));

function normalizeNewlines(input) {
  return input.replace(/\r\n?/g, "\n");
}

function releaseTargetToPlatformKey(target) {
  switch (target) {
    case "aarch64-apple-darwin":
      return "darwin-arm64";
    case "x86_64-apple-darwin":
      return "darwin-x64";
    case "aarch64-unknown-linux-gnu":
      return "linux-arm64";
    case "x86_64-unknown-linux-gnu":
      return "linux-x64";
    case "aarch64-pc-windows-msvc":
      return "win32-arm64";
    case "x86_64-pc-windows-msvc":
      return "win32-x64";
    default:
      throw new Error(`No npm platform mapping for release target ${target}`);
  }
}

function releaseMatrixTargets() {
  const workflow = readFileSync(
    join(repoRoot, ".github", "workflows", "release.yml"),
    "utf8"
  );
  const normalizedWorkflow = normalizeNewlines(workflow);
  assert.match(normalizedWorkflow, /^\s{2}verify-source:$/m, "release source verification job");
  assert.match(normalizedWorkflow, /^\s{4}needs: verify-source$/m, "build requires source verification");
  assert.match(
    normalizedWorkflow,
    /cargo test --workspace --all-targets --locked --no-fail-fast/,
    "locked all-target source tests"
  );
  assert.match(normalizedWorkflow, /cargo build --release --locked --target/, "locked release build");
  assert.match(normalizedWorkflow, /check-version-parity\.mjs "\$GITHUB_REF_NAME"/, "tag parity gate");
  assert.match(normalizedWorkflow, /mcp-stdio-smoke\.mjs/, "MCP stdio release smoke");
  const matrixRows = [...normalizedWorkflow.matchAll(
    /^\s+- target: (\S+)\n\s+os: (\S+)\n\s+artifact: (\S+)$/gm
  )];
  const targets = matrixRows.map((match) => match[1]);
  for (const [, target, , artifact] of matrixRows) {
    assert.strictEqual(artifact, `phantom-${target}`, `release artifact for ${target}`);
  }
  assert.match(normalizedWorkflow, /tar czf .* phantom phantom-mcp/, "Unix archive binaries");
  assert.match(normalizedWorkflow, /7z a .* phantom\.exe phantom-mcp\.exe/, "Windows archive binaries");

  return Object.fromEntries(
    targets
      .map((target) => [releaseTargetToPlatformKey(target), target])
      .sort(([a], [b]) => a.localeCompare(b))
  );
}

assert.strictEqual(normalizeNewlines("first\r\nsecond\rthird"), "first\nsecond\nthird");

function sortedTargets(wrapper) {
  return Object.fromEntries(
    Object.entries(wrapper.SUPPORTED_TARGETS).sort(([a], [b]) =>
      a.localeCompare(b)
    )
  );
}

function assertWrapperMatchesReleaseMatrix(name, wrapper) {
  const expected = releaseMatrixTargets();
  assert.deepStrictEqual(sortedTargets(wrapper), expected, `${name} matrix`);

  for (const [platformKey, target] of Object.entries(expected)) {
    const [platform, arch] = platformKey.split("-");
    assert.strictEqual(
      wrapper.getPlatformTarget({ platform, arch }),
      target,
      `${name} maps ${platformKey}`
    );
  }

  for (const runtime of [
    { platform: "darwin", arch: "ia32" },
    { platform: "linux", arch: "arm" },
    { platform: "freebsd", arch: "x64" },
    { platform: "win32", arch: "ia32" },
  ]) {
    assert.throws(() => wrapper.getPlatformTarget(runtime), (error) => {
      assert.match(error.message, new RegExp(`Unsupported platform: ${runtime.platform}-${runtime.arch}`));
      assert.match(error.message, /releases\/tag\/v0\.7\.4/);
      assert.match(error.message, /checksum-verifiable/);
      assert.doesNotMatch(error.message, /cargo install|npm install|npx |curl[^\n]*\|/i);
      return true;
    }, `${name} rejects ${runtime.platform}-${runtime.arch}`);
  }
}

assertWrapperMatchesReleaseMatrix("phantom-secrets", phantomCli);
assertWrapperMatchesReleaseMatrix("phantom-secrets-mcp", phantomMcp);

for (const wrapperPath of [
  join(repoRoot, "npm", "bin", "cli.js"),
  join(repoRoot, "npm-mcp", "bin", "cli.js"),
]) {
  const source = readFileSync(wrapperPath, "utf8");
  assert.doesNotMatch(source, /Install from source|cargo install phantom-secrets/);
}

console.log("npm wrapper platform matrix tests passed");
