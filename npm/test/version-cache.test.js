// Fixtures follow the independent package carrier, not the wrapper implementation.
const candidateVersion = require("../package.json").version;
const assert = require("assert");
const crypto = require("crypto");
const {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
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
  ("phantom " + candidateVersion + " trailing-text\n"),
  ("phantom " + candidateVersion + "\ntrailing-text"),
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

  writePrivateFile(paths.binaryPath, "unverified", 0o700);
  for (const malformed of ['{"version":', "not JSON", "null", "[]"]) {
    writePrivateFile(paths.manifestPath, malformed, 0o600);
    assert.strictEqual(readVerifiedManifest(paths.binaryPath, paths.manifestPath), null);
    assert.strictEqual(validateCachedBinary(paths.binaryPath, paths.manifestPath, {
      execFileSyncImpl: () => { executions += 1; },
    }), false, "malformed manifest must reject the cached binary");
    rmSync(paths.manifestPath);
  }
  assert.strictEqual(executions, 0, "binary with malformed manifest must never execute");
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
    // is fresh and must be re-verified (spawned) on every call.
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

// A cache root containing spaces must be read as one path: the verified pair is
// found there, the version spawn receives that exact path, and a decoy pair in
// the space-free prefix of the same name is never consulted.
const spacedRoot = mkdtempSync(join(tmpdir(), "phantom cache test "));
try {
  const spacedDir = join(spacedRoot, "my cache dir");
  const decoyDir = join(spacedRoot, "my");
  ensurePrivateCacheDir(decoyDir);
  ensurePrivateCacheDir(spacedDir);
  const spaced = pathSet(spacedDir);
  const decoy = pathSet(decoyDir);
  assert.ok(spaced.binaryPath.startsWith(spacedDir), "binary path stays under the spaced cache dir");
  assert.ok(spaced.manifestPath.startsWith(spacedDir), "manifest path stays under the spaced cache dir");
  writePair(spaced.binaryPath, spaced.manifestPath, "spaced-binary");
  writePair(decoy.binaryPath, decoy.manifestPath, "decoy-binary");

  assert.ok(readVerifiedManifest(spaced.binaryPath, spaced.manifestPath));
  let spawnedPath;
  assert.strictEqual(validateCachedBinary(spaced.binaryPath, spaced.manifestPath, {
    execFileSyncImpl: (path) => {
      spawnedPath = path;
      return Buffer.from("phantom " + candidateVersion + "\n");
    },
  }), true);
  assert.strictEqual(spawnedPath, spaced.binaryPath, "version check runs the binary in the spaced cache dir");
  assert.strictEqual(readFileSync(spaced.binaryPath, "utf8"), "spaced-binary");

  const nextBinary = join(spacedRoot, "next candidate");
  const nextManifest = `${nextBinary}.manifest.json`;
  writePair(nextBinary, nextManifest, "spaced-new");
  replaceCachedBinary(nextBinary, nextManifest, spaced);
  assert.strictEqual(readFileSync(spaced.binaryPath, "utf8"), "spaced-new");
  assert.strictEqual(readFileSync(decoy.binaryPath, "utf8"), "decoy-binary");
} finally {
  rmSync(spacedRoot, { recursive: true, force: true });
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

async function spacedHomeCacheTest() {
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

testMalformedCacheFallback()
  .then(() => spacedHomeCacheTest())
  .then(() => {
    console.log("npm CLI wrapper manifest, version, replacement, and recovery tests passed");
  }).catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
