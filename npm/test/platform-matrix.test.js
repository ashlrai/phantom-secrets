const assert = require("assert");
const { existsSync, mkdtempSync, readFileSync, rmSync } = require("fs");
const { tmpdir } = require("os");
const { join } = require("path");

const {
  SUPPORTED_TARGETS,
  ensureBinary,
  getPlatformTarget,
} = require("../bin/cli.js");

const expected = Object.freeze({
  "darwin-arm64": "aarch64-apple-darwin",
  "darwin-x64": "x86_64-apple-darwin",
  "linux-arm64": "aarch64-unknown-linux-gnu",
  "linux-x64": "x86_64-unknown-linux-gnu",
  "win32-arm64": "aarch64-pc-windows-msvc",
  "win32-x64": "x86_64-pc-windows-msvc",
});

assert.deepStrictEqual(SUPPORTED_TARGETS, expected);

// Keep the published platform table in sync with the executable's exact map.
const readme = readFileSync(join(__dirname, "..", "README.md"), "utf8");
const platformTable = readme.match(
  /\| Operating system \(Node\.js platform\) \| Node\.js architecture \| Native target \|\r?\n\|---\|---\|---\|\r?\n((?:\|[^\n]+\|\r?\n)+)/
);
assert.ok(platformTable, "README must contain the supported platform table");
const documentedTargets = {};
const platformNames = { darwin: "macOS", linux: "Linux with glibc", win32: "Windows" };
for (const row of platformTable[1].trim().split(/\r?\n/)) {
  const match = row.match(/^\| ([^|]+) \(`([^`]+)`\) \| `([^`]+)` \| `([^`]+)` \|$/);
  assert.ok(match, `invalid README platform row: ${row}`);
  const [, name, platform, arch, target] = match;
  assert.strictEqual(name, platformNames[platform], `incorrect OS name for ${platform}`);
  const key = `${platform}-${arch}`;
  assert.ok(!Object.hasOwn(documentedTargets, key), `duplicate README platform: ${key}`);
  documentedTargets[key] = target;
}
assert.deepStrictEqual(documentedTargets, SUPPORTED_TARGETS);

for (const [platformKey, target] of Object.entries(expected)) {
  const [platform, arch] = platformKey.split("-");
  assert.strictEqual(
    getPlatformTarget({ platform, arch }),
    target,
    `phantom-secrets maps ${platformKey}`
  );
}

for (const runtime of [
  { platform: "darwin", arch: "ia32" },
  { platform: "linux", arch: "arm" },
  { platform: "freebsd", arch: "x64" },
  { platform: "win32", arch: "ia32" },
]) {
  assert.throws(() => getPlatformTarget(runtime), (error) => {
    assert.match(error.message, new RegExp(`Unsupported platform: ${runtime.platform}-${runtime.arch}`));
    assert.match(error.message, /releases\/tag\/v0\.7\.9/);
    assert.match(error.message, /checksum-verifiable/);
    assert.doesNotMatch(error.message, /cargo install|npm install|npx |curl[^\n]*\|/i);
    return true;
  });
}

const wrapperSource = readFileSync(join(__dirname, "..", "bin", "cli.js"), "utf8");
assert.doesNotMatch(wrapperSource, /Install from source|cargo install phantom-secrets/);

(async () => {
  const testDir = mkdtempSync(join(tmpdir(), "phantom-cli-unsupported-"));
  const cacheDir = join(testDir, "cache");
  let downloads = 0;
  try {
    await assert.rejects(
      ensureBinary({
        cacheDir,
        runtime: { platform: "freebsd", arch: "x64" },
        downloadImpl: async () => {
          downloads += 1;
          throw new Error("unsupported platforms must not download");
        },
      }),
      /Unsupported platform: freebsd-x64/
    );
    assert.strictEqual(downloads, 0, "unsupported platforms must not attempt a download");
    assert.strictEqual(existsSync(cacheDir), false, "unsupported platforms must not create a cache");
  } finally {
    rmSync(testDir, { recursive: true, force: true });
  }
  console.log("npm CLI wrapper platform matrix tests passed");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
