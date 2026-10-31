const assert = require("assert");
const crypto = require("crypto");
const { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } = require("fs");
const { tmpdir } = require("os");
const { join } = require("path");

const {
  SUPPORTED_TARGETS,
  ensureBinary,
  getPlatformTarget,
  pathSet,
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

const unsupported = [
  { platform: "darwin", arch: "ia32" },
  { platform: "linux", arch: "arm" },
  { platform: "freebsd", arch: "x64" },
  { platform: "openbsd", arch: "x64" },
  { platform: "win32", arch: "ia32" },
];

// The examples in the README must be the combinations exercised below.
const unsupportedTable = readme.match(
  /\| Node\.js platform \| Node\.js architecture \|\r?\n\|---\|---\|\r?\n((?:\|[^\n]+\|\r?\n)+)/
);
assert.ok(unsupportedTable, "README must contain the unsupported platform examples");
const documentedUnsupported = unsupportedTable[1].trim().split(/\r?\n/).map((row) => {
  const match = row.match(/^\| `([^`]+)` \| `([^`]+)` \|$/);
  assert.ok(match, `invalid README unsupported platform row: ${row}`);
  return { platform: match[1], arch: match[2] };
});
assert.deepStrictEqual(documentedUnsupported, unsupported);

for (const runtime of unsupported) {
  assert.throws(() => getPlatformTarget(runtime), (error) => {
    assert.match(error.message, new RegExp(`Unsupported platform: ${runtime.platform}-${runtime.arch}`));
    assert.match(error.message, /releases\/tag\/v0\.8\.0/);
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

  // Even a matching, integrity-valid cache must not bypass OS selection.
  const populatedCache = mkdtempSync(join(tmpdir(), "phantom-cli-unsupported-cache-"));
  try {
    const binary = "cached binary fixture";
    const binaryPath = join(populatedCache, "phantom");
    const manifest = JSON.stringify({
      version: "0.8.0",
      sha256: crypto.createHash("sha256").update(binary).digest("hex"),
    }) + "\n";
    writeFileSync(binaryPath, binary, { mode: 0o700 });
    writeFileSync(`${binaryPath}.manifest.json`, manifest, { mode: 0o600 });
    let executions = 0;
    let downloads = 0;
    let extractions = 0;
    await assert.rejects(
      ensureBinary({
        cacheDir: populatedCache,
        runtime: { platform: "openbsd", arch: "x64" },
        execFileSyncImpl: () => { executions += 1; return Buffer.from("phantom 0.8.0\n"); },
        downloadImpl: async () => { downloads += 1; throw new Error("unexpected download"); },
        extractImpl: () => { extractions += 1; },
      }),
      /Unsupported platform: openbsd-x64/
    );
    assert.strictEqual(executions, 0, "unsupported platforms must not execute a cached binary");
    assert.strictEqual(downloads, 0, "unsupported platforms must not attempt a download");
    assert.strictEqual(extractions, 0, "unsupported platforms must not extract a binary");
    assert.strictEqual(existsSync(pathSet(populatedCache, "openbsd").lockPath), false);
    assert.deepStrictEqual(readdirSync(populatedCache).sort(), ["phantom", "phantom.manifest.json"]);
    assert.strictEqual(readFileSync(binaryPath, "utf8"), binary);
    assert.strictEqual(readFileSync(`${binaryPath}.manifest.json`, "utf8"), manifest);
  } finally {
    rmSync(populatedCache, { recursive: true, force: true });
  }
  console.log("npm CLI wrapper platform matrix tests passed");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
