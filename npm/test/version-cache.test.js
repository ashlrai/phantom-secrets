// Fixtures follow the independent package carrier, not the wrapper implementation.
const candidateVersion = require("../package.json").version;
const assert = require("assert");
const crypto = require("crypto");
const {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
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
  ensurePrivateCacheDir,
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
  ("phantom v" + candidateVersion + "\n"),
  "phantom 0.7.01\n",
  "phantom 1.2.3-01\n",
  ("phantom " + candidateVersion + "-untrusted\nextra\n"),
  ("prefix phantom " + candidateVersion + "\n"),
  ("phantom-mcp " + candidateVersion + "\n"),
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

  if (process.platform !== "win32") {
    // Freshness boundary: a cached binary is trusted from its attestation only
    // once its newest timestamp is at least 2 s old (>=). One nanosecond younger
    // is "fresh" and must be re-verified (spawned) on every call.
    const settleNs = 2_000_000_000n;
    const boundaryBinary = join(fixtureDir, "boundary-binary");
    const boundaryManifest = `${boundaryBinary}.manifest.json`;
    const okVersion = () => Buffer.from(("phantom " + candidateVersion + "\n"));
    const pinAge = (ageNs) => {
      const { mtimeNs, ctimeNs } = lstatSync(boundaryBinary, { bigint: true });
      const newest = mtimeNs > ctimeNs ? mtimeNs : ctimeNs;
      setAttestationClockForTest(() => newest + ageNs);
    };
    try {
      for (const [ageNs, trusted] of [[settleNs - 1n, false], [settleNs, true], [settleNs + 1n, true]]) {
        rmSync(boundaryBinary, { force: true });
        rmSync(boundaryManifest, { force: true });
        rmSync(attestationPath(boundaryBinary), { force: true });
        writePair(boundaryBinary, boundaryManifest, "boundary-binary");
        pinAge(ageNs);
        let spawns = 0;
        const counting = () => { spawns += 1; return okVersion(); };
        assert.strictEqual(validateCachedBinary(boundaryBinary, boundaryManifest, { execFileSyncImpl: counting }), true);
        assert.strictEqual(spawns, 1, `age ${ageNs}ns: first call verifies in full`);
        assert.strictEqual(existsSync(attestationPath(boundaryBinary)), trusted, `age ${ageNs}ns: attested=${trusted}`);
        assert.strictEqual(validateCachedBinary(boundaryBinary, boundaryManifest, { execFileSyncImpl: counting }), true);
        assert.strictEqual(spawns, trusted ? 1 : 2, `age ${ageNs}ns: repeat call ${trusted ? "uses the attestation" : "re-verifies"}`);
      }
    } finally {
      setAttestationClockForTest(null);
    }
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

console.log("npm CLI wrapper manifest, version, replacement, and recovery tests passed");
