// Fixtures follow the independent package carrier, not the wrapper implementation.
const candidateVersion = require("../package.json").version;
const assert = require("assert");
const crypto = require("crypto");
const {
  chmodSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
} = require("fs");
const { tmpdir } = require("os");
const { join } = require("path");

const {
  attestationPath,
  ensureBinary,
  ensurePrivateCacheDir,
  getCacheDir,
  setAttestationClockForTest,
  isCachedBinaryStale,
  parseBinaryVersion,
  pathSet,
  readVerifiedManifest,
  recoverInterruptedInstall,
  replaceCachedBinary,
  validateCachedBinary,
  writePrivateFile,
} = require("../bin/cli.js");

function writePair(binaryPath, manifestPath, contents) {
  writePrivateFile(binaryPath, contents, 0o700);
  const sha256 = crypto.createHash("sha256").update(contents).digest("hex");
  writePrivateFile(manifestPath, `${JSON.stringify({ version: candidateVersion, sha256 })}\n`, 0o600);
}

assert.strictEqual(parseBinaryVersion(("phantom " + candidateVersion + "\n")), candidateVersion);
assert.strictEqual(parseBinaryVersion(("phantom " + candidateVersion + "\r\n")), candidateVersion);
assert.strictEqual(
  parseBinaryVersion(Buffer.from("phantom 1.2.3-rc.1+build.7\n")),
  "1.2.3-rc.1+build.7"
);
for (const malformed of [
  "",
  "phantom\n",
  "phantom 1.2\n",
  ("phantom v" + candidateVersion + "\n"),
  "phantom 01.2.3\n",
  "phantom 0.7.01\n",
  "phantom 1.2.3-01\n",
  (" phantom " + candidateVersion + "\n"),
  ("\tphantom " + candidateVersion + "\n"),
  ("phantom " + candidateVersion + "-untrusted\nextra\n"),
  ("prefix phantom " + candidateVersion + "\n"),
  ("phantom-mcp " + candidateVersion + "\n"),
  // Unrelated executable names followed by an otherwise valid version.
  ("node " + candidateVersion + "\n"),
  ("curl " + candidateVersion + "\r\n"),
  ("Phantom " + candidateVersion + "\n"),
  ("/usr/bin/phantom " + candidateVersion + "\n"),
  ("phantomx " + candidateVersion + "\n"),
]) assert.strictEqual(parseBinaryVersion(malformed), null, malformed);

const fixtureDir = mkdtempSync(join(tmpdir(), "phantom-cache-test-"));
try {
  ensurePrivateCacheDir(fixtureDir);
  const paths = pathSet(fixtureDir);
  writePrivateFile(paths.binaryPath, "unverified", 0o700);
  let executions = 0;
  assert.strictEqual(validateCachedBinary(paths.binaryPath, paths.manifestPath, {
    execFileSyncImpl: () => {
      executions += 1;
      return Buffer.from(("phantom " + candidateVersion + "\n"));
    },
  }), false);
  assert.strictEqual(executions, 0, "binary without manifest must never execute");
  rmSync(paths.binaryPath);

  writePair(paths.binaryPath, paths.manifestPath, "old-binary");
  // Treat the fixture as settled (10 s old) so the attestation path is used.
  setAttestationClockForTest(() => BigInt(Date.now() + 10_000) * 1_000_000n);
  assert.ok(readVerifiedManifest(paths.binaryPath, paths.manifestPath));
  assert.strictEqual(isCachedBinaryStale(paths.binaryPath, {
    execFileSyncImpl: () => Buffer.from(("phantom " + candidateVersion + "\n")),
  }), false);

  // The passing version check above is attested for this exact binary, so a
  // repeat call must not spawn. Drop the attestation so the bounded timeout
  // path below still runs against a real version spawn.
  assert.strictEqual(validateCachedBinary(paths.binaryPath, paths.manifestPath, {
    execFileSyncImpl: () => { throw new Error("attested binary must not re-run --version"); },
  }), true);
  rmSync(attestationPath(paths.binaryPath));
  setAttestationClockForTest(null);

  let observedTimeout;
  assert.strictEqual(validateCachedBinary(paths.binaryPath, paths.manifestPath, {
    execTimeoutMs: 1234,
    execFileSyncImpl: (_path, _args, options) => {
      observedTimeout = options.timeout;
      const error = new Error("simulated hung child");
      error.code = "ETIMEDOUT";
      throw error;
    },
  }), false);
  assert.strictEqual(observedTimeout, 1234);

  if (process.platform !== "win32") {
    const hungBinary = join(fixtureDir, "hung-binary");
    const hungManifest = `${hungBinary}.manifest.json`;
    writePair(hungBinary, hungManifest, "#!/bin/sh\nwhile :; do :; done\n");
    const started = Date.now();
    assert.strictEqual(validateCachedBinary(hungBinary, hungManifest, {
      execTimeoutMs: 50,
    }), false);
    assert.ok(Date.now() - started < 2000, "hung version child must be killed by timeout");
  }

  const candidatePath = join(fixtureDir, "candidate");
  const candidateManifestPath = `${candidatePath}.manifest.json`;
  writePair(candidatePath, candidateManifestPath, "new-binary");
  replaceCachedBinary(candidatePath, candidateManifestPath, paths);
  assert.strictEqual(readFileSync(paths.binaryPath, "utf8"), "new-binary");
  assert.ok(readVerifiedManifest(paths.binaryPath, paths.manifestPath));

  rmSync(paths.binaryPath);
  rmSync(paths.manifestPath);
  writePair(paths.backupBinaryPath, paths.backupManifestPath, "recover-me");
  writePrivateFile(paths.transactionPath, "{}\n", 0o600);
  assert.strictEqual(recoverInterruptedInstall(paths), "restored-backup");
  assert.strictEqual(readFileSync(paths.binaryPath, "utf8"), "recover-me");

  renameSync(paths.binaryPath, paths.backupBinaryPath);
  renameSync(paths.manifestPath, paths.backupManifestPath);
  writePrivateFile(paths.binaryPath, "incomplete-candidate", 0o700);
  writePrivateFile(paths.transactionPath, "{}\n", 0o600);
  assert.strictEqual(recoverInterruptedInstall(paths), "restored-backup");
  assert.strictEqual(readFileSync(paths.binaryPath, "utf8"), "recover-me");

  rmSync(paths.binaryPath);
  if (process.platform !== "win32") {
    symlinkSync(paths.backupBinaryPath, paths.binaryPath);
    assert.strictEqual(readVerifiedManifest(paths.binaryPath, paths.manifestPath), null);
    rmSync(paths.binaryPath);
  }
  writePrivateFile(paths.binaryPath, "linked", 0o700);
  const secondLink = join(fixtureDir, "second-link");
  linkSync(paths.binaryPath, secondLink);
  assert.strictEqual(readVerifiedManifest(paths.binaryPath, paths.manifestPath), null);
  chmodSync(secondLink, 0o700);
} finally {
  rmSync(fixtureDir, { recursive: true, force: true });
}

// A home directory containing spaces must resolve to one cache path, and a
// valid cached binary there must be reused without any network access.
async function spacedCachePathTest() {
  const root = mkdtempSync(join(tmpdir(), "phantom cache test "));
  try {
    const home = join(root, "Home Dir With Spaces");
    mkdirSync(home, { recursive: true });
    const cacheDir = getCacheDir({ env: { HOME: home }, homedirImpl: () => home });
    assert.strictEqual(cacheDir, join(home, ".phantom-secrets", "bin"));
    assert.ok(cacheDir.includes(" "), "fixture cache path must contain spaces");

    ensurePrivateCacheDir(cacheDir);
    const spaced = pathSet(cacheDir);
    writePair(spaced.binaryPath, spaced.manifestPath, "cached-binary");

    const spawned = [];
    const noNetwork = () => { throw new Error("cached binary must not trigger a download"); };
    const resolved = await ensureBinary({
      cacheDir,
      downloadImpl: noNetwork,
      extractImpl: noNetwork,
      execFileSyncImpl: (path, args) => {
        spawned.push([path, args]);
        return Buffer.from("phantom " + candidateVersion + "\n");
      },
    });
    assert.strictEqual(resolved, spaced.binaryPath, "cache must be read from the intended spaced path");
    assert.deepStrictEqual(spawned, [[spaced.binaryPath, ["--version"]]]);

  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

spacedCachePathTest().then(() => {
console.log("npm CLI wrapper manifest, version, replacement, and recovery tests passed");
}, (error) => {
  console.error(error);
  process.exit(1);
});
