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
  writePrivateFile(manifestPath, `${JSON.stringify({ version: "0.7.5", sha256 })}\n`, 0o600);
}

assert.strictEqual(parseBinaryVersion("phantom-mcp 0.7.5\n"), "0.7.5");
assert.strictEqual(parseBinaryVersion("phantom-mcp 0.7.5\r\n"), "0.7.5");
assert.strictEqual(
  parseBinaryVersion(Buffer.from("phantom-mcp 1.2.3-rc.1+build.7\n")),
  "1.2.3-rc.1+build.7"
);
for (const malformed of [
  "",
  "phantom-mcp\n",
  "phantom-mcp v0.7.5\n",
  "phantom-mcp 0.7.01\n",
  "phantom-mcp 1.2.3-01\n",
  "phantom-mcp 0.7.5-untrusted\nextra\n",
  "prefix phantom-mcp 0.7.5\n",
  "phantom 0.7.5\n",
]) assert.strictEqual(parseBinaryVersion(malformed), null, malformed);

const fixtureDir = mkdtempSync(join(tmpdir(), "phantom-mcp-cache-test-"));
try {
  ensurePrivateCacheDir(fixtureDir);
  const paths = pathSet(fixtureDir);
  writePrivateFile(paths.binaryPath, "unverified", 0o700);
  let executions = 0;
  assert.strictEqual(validateCachedBinary(paths.binaryPath, paths.manifestPath, {
    execFileSyncImpl: () => {
      executions += 1;
      return Buffer.from("phantom-mcp 0.7.5\n");
    },
  }), false);
  assert.strictEqual(executions, 0, "binary without manifest must never execute");
  rmSync(paths.binaryPath);

  writePair(paths.binaryPath, paths.manifestPath, "old-binary");
  assert.ok(readVerifiedManifest(paths.binaryPath, paths.manifestPath));
  assert.strictEqual(isCachedBinaryStale(paths.binaryPath, {
    execFileSyncImpl: () => Buffer.from("phantom-mcp 0.7.5\n"),
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

console.log("npm MCP wrapper manifest, version, replacement, and recovery tests passed");
