// Fixtures follow the independent package carrier, not the wrapper implementation.
const candidateVersion = require("../package.json").version;
const assert = require("assert");
const crypto = require("crypto");
const {
  chmodSync,
  linkSync,
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
  getPlatformTarget,
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
  let emptyCacheExecutions = 0;
  const emptyCacheOptions = {
    execFileSyncImpl: () => { emptyCacheExecutions += 1; throw new Error("missing binary executed"); },
  };
  assert.strictEqual(readVerifiedManifest(paths.binaryPath, paths.manifestPath), null);
  assert.strictEqual(validateCachedBinary(paths.binaryPath, paths.manifestPath, emptyCacheOptions), false);
  assert.strictEqual(isCachedBinaryStale(paths.binaryPath, emptyCacheOptions), true);
  assert.strictEqual(emptyCacheExecutions, 0, "empty cache must never execute a binary");

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

  // Empty cache fixtures: a zero-byte file is never a valid cached version.
  // Each case must fail closed without ever executing the binary (offline).
  const neverExec = {
    execFileSyncImpl: () => { throw new Error("empty cache entry must never execute"); },
  };
  const emptyBinary = join(fixtureDir, "empty-binary");
  const emptyManifest = `${emptyBinary}.manifest.json`;
  // 1. Empty binary with a manifest whose digest matches the empty content.
  writePair(emptyBinary, emptyManifest, "");
  assert.strictEqual(readVerifiedManifest(emptyBinary, emptyManifest), null);
  assert.strictEqual(validateCachedBinary(emptyBinary, emptyManifest, neverExec), false);
  assert.strictEqual(isCachedBinaryStale(emptyBinary, neverExec), true);
  rmSync(emptyBinary);
  rmSync(emptyManifest);
  // 2. Real binary with an empty manifest file.
  writePrivateFile(emptyBinary, "real-binary", 0o700);
  writePrivateFile(emptyManifest, "", 0o600);
  assert.strictEqual(readVerifiedManifest(emptyBinary, emptyManifest), null);
  assert.strictEqual(validateCachedBinary(emptyBinary, emptyManifest, neverExec), false);
  rmSync(emptyBinary);
  rmSync(emptyManifest);
  // 3. Both empty.
  writePrivateFile(emptyBinary, "", 0o700);
  writePrivateFile(emptyManifest, "", 0o600);
  assert.strictEqual(validateCachedBinary(emptyBinary, emptyManifest, neverExec), false);
  rmSync(emptyBinary);
  rmSync(emptyManifest);

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

async function testMalformedCacheFallback() {
  const cacheDir = mkdtempSync(join(tmpdir(), "phantom-malformed-cache-"));
  try {
    const paths = pathSet(cacheDir);
    writePrivateFile(paths.binaryPath, "malformed-cache-binary", 0o700);
    writePrivateFile(paths.manifestPath, '{"version":', 0o600);
    const archive = Buffer.from("archive fixture");
    const replacement = Buffer.from("replacement binary");
    const archiveName = `phantom-${getPlatformTarget(process)}.${process.platform === "win32" ? "zip" : "tar.gz"}`;
    const digest = crypto.createHash("sha256").update(archive).digest("hex");
    const downloads = [];
    let executions = 0;
    const result = await ensureBinary({
      cacheDir,
      downloadImpl: async (url) => {
        downloads.push(url);
        return url.endsWith(".sha256") ? Buffer.from(`${digest}  ${archiveName}\n`) : archive;
      },
      extractImpl: (_archivePath, candidatePath) => writePrivateFile(candidatePath, replacement, 0o700),
      execFileSyncImpl: (binaryPath, args) => {
        executions += 1;
        assert.notStrictEqual(binaryPath, paths.binaryPath, "malformed cache must not execute");
        assert.deepStrictEqual(args, ["--version"]);
        assert.deepStrictEqual(readFileSync(binaryPath), replacement);
        return Buffer.from(`phantom ${candidateVersion}\n`);
      },
    });
    assert.strictEqual(result, paths.binaryPath);
    assert.strictEqual(downloads.length, 2, "fallback must request checksum and archive through the stub");
    assert.ok(downloads[0].endsWith(`${archiveName}.sha256`));
    assert.ok(downloads[1].endsWith(archiveName));
    assert.strictEqual(executions, 1);
    assert.deepStrictEqual(readFileSync(paths.binaryPath), replacement);
    assert.ok(readVerifiedManifest(paths.binaryPath, paths.manifestPath));
  } finally {
    rmSync(cacheDir, { recursive: true, force: true });
  }
}

testMalformedCacheFallback().then(() => {
  console.log("npm CLI wrapper manifest, version, replacement, and recovery tests passed");
}).catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
