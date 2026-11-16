// Fixtures follow the independent package carrier, not the wrapper implementation.
const candidateVersion = require("../package.json").version;
const assert = require("assert");
const crypto = require("crypto");
const { spawnSync } = require("child_process");
const {
  chmodSync,
  copyFileSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} = require("fs");
const { tmpdir } = require("os");
const { join } = require("path");

const {
  ensureBinary,
  ensurePrivateCacheDir,
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

assert.strictEqual(parseBinaryVersion(("phantom-mcp " + candidateVersion + "\n")), candidateVersion);
assert.strictEqual(parseBinaryVersion(("phantom-mcp " + candidateVersion + "\r\n")), candidateVersion);
assert.strictEqual(parseBinaryVersion("phantom-mcp " + candidateVersion), candidateVersion);
assert.strictEqual(
  parseBinaryVersion(Buffer.from("phantom-mcp 1.2.3-rc.1+build.7\n")),
  "1.2.3-rc.1+build.7"
);
for (const malformed of [
  "",
  "phantom-mcp\n",
  ("phantom-mcp v" + candidateVersion + "\n"),
  "phantom-mcp 0.7.01\n",
  "phantom-mcp 1.2.3-01\n",
  ("phantom-mcp " + candidateVersion + "-untrusted\nextra\n"),
  ("prefix phantom-mcp " + candidateVersion + "\n"),
  ("phantom " + candidateVersion + "\n"),
  ("phantom-mcp " + candidateVersion + "\n\n"),
  ("phantom-mcp " + candidateVersion + "\r\n\n"),
  ("phantom-mcp " + candidateVersion + "\u2028"),
  ("phantom-mcp " + candidateVersion + "\u2029"),
  ("phantom-mcp " + candidateVersion + "\0"),
]) assert.strictEqual(parseBinaryVersion(malformed), null, malformed);

const fixtureDir = mkdtempSync(join(tmpdir(), "phantom-mcp-cache-test-"));
try {
  const packageDir = join(fixtureDir, "package");
  const binDir = join(packageDir, "bin");
  mkdirSync(binDir, { recursive: true });
  copyFileSync(join(__dirname, "../bin/package-version.js"), join(binDir, "package-version.js"));
  for (const version of [candidateVersion, ""]) {
    writeFileSync(join(packageDir, "package.json"), JSON.stringify({ version }));
    const result = spawnSync(process.execPath, [join(binDir, "package-version.js")], {
      encoding: "utf8",
    });
    assert.ifError(result.error);
    if (version === "") {
      assert.strictEqual(typeof result.status, "number", "version check must exit normally");
      assert.notStrictEqual(result.status, 0, "empty packaged version must be rejected");
      assert.match(result.stderr, /invalid packaged Phantom version/);
    } else {
      assert.strictEqual(result.status, 0, result.stderr);
    }
  }

  ensurePrivateCacheDir(fixtureDir);
  const paths = pathSet(fixtureDir);
  writePrivateFile(paths.binaryPath, "unverified", 0o700);
  let executions = 0;
  assert.strictEqual(validateCachedBinary(paths.binaryPath, paths.manifestPath, {
    execFileSyncImpl: () => {
      executions += 1;
      return Buffer.from(("phantom-mcp " + candidateVersion + "\n"));
    },
  }), false);
  assert.strictEqual(executions, 0, "binary without manifest must never execute");
  rmSync(paths.binaryPath);

  // A matching manifest alone cannot turn an empty file into a usable binary.
  writePair(paths.binaryPath, paths.manifestPath, "");
  assert.strictEqual(validateCachedBinary(paths.binaryPath, paths.manifestPath), false);
  assert.strictEqual(isCachedBinaryStale(paths.binaryPath), true);
  rmSync(paths.binaryPath);
  rmSync(paths.manifestPath);

  writePair(paths.binaryPath, paths.manifestPath, "old-binary");
  assert.ok(readVerifiedManifest(paths.binaryPath, paths.manifestPath));
  assert.strictEqual(isCachedBinaryStale(paths.binaryPath, {
    execFileSyncImpl: () => Buffer.alloc(0),
  }), true, "empty version output must not validate a cached binary");
  assert.strictEqual(isCachedBinaryStale(paths.binaryPath, {
    execFileSyncImpl: () => Buffer.from(("phantom-mcp " + candidateVersion + "\n")),
  }), false);

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

(async () => {
  for (const [description, manifest] of [["malformed", '{"version":'], ["empty", ""]]) {
    const cacheDir = mkdtempSync(join(tmpdir(), "phantom-mcp-invalid-cache-"));
    try {
      const paths = pathSet(cacheDir);
      writePrivateFile(paths.binaryPath, "untrusted-cache", 0o700);
      writePrivateFile(paths.manifestPath, manifest, 0o600);
      assert.strictEqual(readVerifiedManifest(paths.binaryPath, paths.manifestPath), null,
        `${description} manifest must be unusable`);
      const archive = Buffer.from("offline archive fixture");
      const checksum = crypto.createHash("sha256").update(archive).digest("hex");
      let downloads = 0;
      let executions = 0;
      const resolved = await ensureBinary({
        cacheDir,
        downloadImpl: async (url) => {
          downloads += 1;
          if (url.endsWith(".sha256")) {
            const archiveName = url.split("/").pop().slice(0, -7);
            return Buffer.from(`${checksum}  ${archiveName}\n`);
          }
          return archive;
        },
        extractImpl: (_archivePath, candidatePath) => {
          writePrivateFile(candidatePath, "replacement-binary", 0o700);
        },
        execFileSyncImpl: (binaryPath) => {
          executions += 1;
          assert.notStrictEqual(binaryPath, paths.binaryPath, `${description} cache must not execute`);
          return Buffer.from(`phantom-mcp ${candidateVersion}\n`);
        },
      });
      assert.strictEqual(resolved, paths.binaryPath);
      assert.strictEqual(downloads, 2, "fallback fetches checksum and archive through the stub");
      assert.strictEqual(executions, 1, "only the replacement binary is checked");
      assert.strictEqual(readFileSync(paths.binaryPath, "utf8"), "replacement-binary");
      assert.ok(readVerifiedManifest(paths.binaryPath, paths.manifestPath));
    } finally {
      rmSync(cacheDir, { recursive: true, force: true });
    }
  }
  console.log("npm MCP wrapper manifest, version, replacement, and recovery tests passed");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
