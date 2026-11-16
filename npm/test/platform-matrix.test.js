// Fixtures follow the independent package carrier, not the wrapper implementation.
const candidateVersion = require("../package.json").version;
const assert = require("assert");
const crypto = require("crypto");
const http = require("http");
const https = require("https");
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

for (const [platformKey, target] of Object.entries(SUPPORTED_TARGETS)) {
  if (platformKey.startsWith("win32-")) {
    assert.match(target, /windows-msvc$/, `${platformKey} must target windows-msvc`);
  }
}

assert.deepStrictEqual(SUPPORTED_TARGETS, expected);

// Every supported mapping must name a real target: a non-empty, non-blank string.
// Checked on the exported map itself so an empty or non-string entry fails here.
function assertTargetsAreNonEmptyStrings(targets) {
  const entries = Object.entries(targets);
  assert.ok(entries.length > 0, "supported platform map must not be empty");
  for (const [platformKey, target] of entries) {
    assert.strictEqual(typeof target, "string", `target for ${platformKey} must be a string`);
    assert.ok(target.trim().length > 0, `target for ${platformKey} must not be empty`);
  }
}
assertTargetsAreNonEmptyStrings(SUPPORTED_TARGETS);

// Prove the check rejects bad targets.
for (const bad of ["", "   ", null, undefined, 42, {}, []]) {
  assert.throws(
    () => assertTargetsAreNonEmptyStrings({ ...SUPPORTED_TARGETS, "linux-x64": bad }),
    assert.AssertionError,
    `bad target ${JSON.stringify(bad)} must fail`
  );
}

// Release binaries link against glibc, so every Linux target must end in `linux-gnu`
// (a musl or other suffix would download a binary the release does not ship).
function assertLinuxTargetsAreGnu(targets, label) {
  const linuxKeys = Object.keys(targets).filter((key) => key.startsWith("linux-"));
  assert.ok(linuxKeys.length > 0, `${label} must contain at least one Linux target`);
  for (const key of linuxKeys) {
    assert.ok(
      targets[key].endsWith("linux-gnu"),
      `${label}: Linux target ${key} must end in linux-gnu, got ${targets[key]}`
    );
  }
}
assertLinuxTargetsAreGnu(SUPPORTED_TARGETS, "SUPPORTED_TARGETS");
assertLinuxTargetsAreGnu(expected, "expected fixture");
for (const suffix of ["linux-musl", "linux-gnueabihf", "linux-android", "linux"]) {
  assert.throws(
    () => assertLinuxTargetsAreGnu({ "linux-x64": `x86_64-unknown-${suffix}` }, "mutant"),
    /must end in linux-gnu/,
    `suffix ${suffix} must be rejected`
  );
}

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
assertLinuxTargetsAreGnu(documentedTargets, "README platform table");

for (const [platformKey, target] of Object.entries(expected)) {
  const [platform, arch] = platformKey.split("-");
  assert.strictEqual(
    getPlatformTarget({ platform, arch }),
    target,
    `phantom-secrets maps ${platformKey}`
  );
}

// Two runtime pairs sharing one target triple would download the wrong binary.
function assertDistinctTargets(resolve, pairs, label) {
  const owners = new Map();
  for (const key of pairs) {
    const [platform, arch] = key.split("-");
    const target = resolve({ platform, arch }, key);
    assert.ok(target, `${label}: ${key} has no target triple`);
    assert.ok(
      !owners.has(target),
      `${label}: duplicate target triple ${target} for ${owners.get(target)} and ${key}`
    );
    owners.set(target, key);
  }
}

const supportedPairs = Object.keys(SUPPORTED_TARGETS);
assertDistinctTargets((runtime) => getPlatformTarget(runtime), supportedPairs, "getPlatformTarget");
assertDistinctTargets((_, key) => SUPPORTED_TARGETS[key], supportedPairs, "SUPPORTED_TARGETS");
assertDistinctTargets((_, key) => documentedTargets[key], Object.keys(documentedTargets), "README");

// The check must actually fail on a duplicate.
assert.throws(
  () => assertDistinctTargets(() => "x86_64-unknown-linux-gnu", ["linux-x64", "linux-arm64"], "fixture"),
  /duplicate target triple x86_64-unknown-linux-gnu for linux-x64 and linux-arm64/
);

// Repeated selection is local and stable for every supported package target.
const networkMethods = [[http, "get"], [http, "request"], [https, "get"], [https, "request"], [globalThis, "fetch"]];
const originalMethods = networkMethods.map(([object, name]) => object[name]);
try {
  for (const [object, name] of networkMethods) {
    object[name] = () => { throw new Error("platform lookup must not access the network"); };
  }
  for (const [platformKey, target] of Object.entries(expected)) {
    const [platform, arch] = platformKey.split("-");
    const runtime = { platform, arch };
    const first = getPlatformTarget(runtime);
    const second = getPlatformTarget(runtime);
    assert.strictEqual(first, target, `first lookup maps ${platformKey}`);
    assert.strictEqual(second, first, `repeated lookup maps ${platformKey} identically`);
  }
} finally {
  networkMethods.forEach(([object, name], index) => { object[name] = originalMethods[index]; });
}

const unsupported = [
  { platform: "darwin", arch: "ia32" },
  { platform: "linux", arch: "arm" },
  { platform: "linux", arch: "riscv64" },
  { platform: "freebsd", arch: "x64" },
  { platform: "freebsd", arch: "arm64" },
  { platform: "openbsd", arch: "x64" },
  { platform: "sunos", arch: "arm" },
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
    assert.match(error.message, new RegExp("releases\\/tag\\/v" + candidateVersion.replaceAll(".", "\\.") + "",""));
    assert.match(error.message, /checksum-verifiable/);
    assert.doesNotMatch(error.message, /cargo install|npm install|npx |curl[^\n]*\|/i);
    return true;
  });
}

// An unsupported Linux architecture is named exactly, never mapped to a Linux target.
assert.throws(() => getPlatformTarget({ platform: "linux", arch: "riscv64" }), (error) => {
  assert.ok(error.message.includes("Unsupported platform: linux-riscv64"), error.message);
  assert.doesNotMatch(error.message, /x86_64|aarch64/);
  return true;
});

function assertUnsupported(runtime) {
  assert.throws(() => getPlatformTarget(runtime), (error) => {
    assert.match(error.message, new RegExp(`Unsupported platform: ${runtime.platform}-${runtime.arch}`));
    assert.match(error.message, new RegExp("releases\\/tag\\/v" + candidateVersion.replaceAll(".", "\\.") + "",""));
    assert.match(error.message, /checksum-verifiable/);
    assert.doesNotMatch(error.message, /cargo install|npm install|npx |curl[^\n]*\|/i);
    return true;
  });
}

// Lookups are pure: repeated calls agree and neither input nor mapping changes.
const mappingBefore = JSON.stringify(SUPPORTED_TARGETS);
for (const [platformKey, target] of Object.entries(expected)) {
  const [platform, arch] = platformKey.split("-");
  const runtime = Object.freeze({ platform, arch });
  assert.strictEqual(getPlatformTarget(runtime), target);
  assert.strictEqual(getPlatformTarget(runtime), target, `repeat lookup of ${platformKey}`);
  assert.deepStrictEqual(runtime, { platform, arch }, "lookup must not change its input");
}
for (const runtime of unsupported) {
  const copy = { ...runtime };
  assertUnsupported(runtime);
  assert.deepStrictEqual(runtime, copy, "failed lookup must not change its input");
}
assert.strictEqual(JSON.stringify(SUPPORTED_TARGETS), mappingBefore, "lookups must not change the mapping");

// Empty platform or architecture must not select a host package.
assertUnsupported({ platform: "linux", arch: "" });
assertUnsupported({ platform: "", arch: "x64" });
// A known architecture must not cause an unsupported OS to select another binary.
assertUnsupported({ platform: "sunos", arch: "x64" });
for (const platform of ["aix", "android", "haiku", "netbsd", "sunos"]) {
  for (const arch of ["x64", "arm64"]) {
    assertUnsupported({ platform, arch });
  }
}

const wrapperSource = readFileSync(join(__dirname, "..", "bin", "cli.js"), "utf8");
assert.doesNotMatch(wrapperSource, /Install from source|cargo install phantom-secrets/);

(async () => {
  const testDir = mkdtempSync(join(tmpdir(), "phantom-cli-unsupported-"));
  const cacheDir = join(testDir, "cache");
  let downloads = 0;
  try {
    for (const runtime of [{ platform: "freebsd", arch: "x64" }, { platform: "sunos", arch: "arm" }]) {
      await assert.rejects(
        ensureBinary({
          cacheDir,
          runtime,
          downloadImpl: async () => {
            downloads += 1;
            throw new Error("unsupported platforms must not download");
          },
        }),
        (error) => error.message.includes(`Unsupported platform: ${runtime.platform}-${runtime.arch}`)
      );
    }
    assert.strictEqual(downloads, 0, "unsupported platforms must not attempt a download");
    assert.strictEqual(existsSync(cacheDir), false, "unsupported platforms must not create a cache");
  } finally {
    rmSync(testDir, { recursive: true, force: true });
  }

  // Unsupported runtimes are rejected before any package is selected or cached.
  const rejectedRuntimes = [
    { platform: "linux", arch: "arm" },
    { platform: "linux", arch: "" },
    { platform: "", arch: "x64" },
  ];
  for (const platform of ["aix", "android", "haiku", "netbsd", "sunos"]) {
    for (const arch of ["x64", "arm64"]) rejectedRuntimes.push({ platform, arch });
  }
  for (const runtime of rejectedRuntimes) {
    const root = mkdtempSync(join(tmpdir(), "phantom-cli-unsupported-extra-"));
    const rejectedCache = join(root, "cache");
    const calls = [];
    try {
      await assert.rejects(
        ensureBinary({
          cacheDir: rejectedCache,
          runtime,
          execFileSyncImpl: () => { calls.push("exec"); return Buffer.alloc(0); },
          downloadImpl: async () => { calls.push("download"); throw new Error("unexpected download"); },
          extractImpl: () => { calls.push("extract"); },
        }),
        (error) => error.message.startsWith(`Unsupported platform: ${runtime.platform}-${runtime.arch}.`)
      );
      assert.deepStrictEqual(calls, [], `${runtime.platform}-${runtime.arch} must not select or run a package`);
      assert.strictEqual(existsSync(rejectedCache), false, `${runtime.platform}-${runtime.arch} must not create a cache`);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }

  // Even a matching, integrity-valid cache must not bypass platform selection.
  const populatedCache = mkdtempSync(join(tmpdir(), "phantom-cli-unsupported-cache-"));
  try {
    const binary = "cached binary fixture";
    const binaryPath = join(populatedCache, "phantom");
    const manifest = JSON.stringify({
      version: candidateVersion,
      sha256: crypto.createHash("sha256").update(binary).digest("hex"),
    }) + "\n";
    writeFileSync(binaryPath, binary, { mode: 0o700 });
    writeFileSync(`${binaryPath}.manifest.json`, manifest, { mode: 0o600 });
    let executions = 0;
    let downloads = 0;
    let extractions = 0;
    for (const runtime of [
      { platform: "openbsd", arch: "x64" },
      { platform: "linux", arch: "arm" },
    ]) {
      await assert.rejects(
        ensureBinary({
          cacheDir: populatedCache,
          runtime,
          execFileSyncImpl: () => { executions += 1; return Buffer.from(("phantom " + candidateVersion + "\n")); },
          downloadImpl: async () => { downloads += 1; throw new Error("unexpected download"); },
          extractImpl: () => { extractions += 1; },
        }),
        new RegExp(`Unsupported platform: ${runtime.platform}-${runtime.arch}`)
      );
      assert.strictEqual(existsSync(pathSet(populatedCache, runtime.platform).lockPath), false);
    }
    assert.strictEqual(executions, 0, "unsupported platforms must not execute a cached binary");
    assert.strictEqual(downloads, 0, "unsupported platforms must not attempt a download");
    assert.strictEqual(extractions, 0, "unsupported platforms must not extract a binary");
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
