// Fixtures follow the independent package carrier, not the wrapper implementation.
const candidateVersion = require("../package.json").version;
const assert = require("assert");
const crypto = require("crypto");
const { mkdtempSync, readFileSync, readdirSync, rmSync } = require("fs");
const { tmpdir } = require("os");
const { basename, dirname, join } = require("path");

const { ensureBinary, pathSet, validateCachedBinary, writePrivateFile } = require("../bin/cli.js");

(async () => {
  const cacheDir = mkdtempSync(join(tmpdir(), "phantom-mcp-valid-cache-"));
  try {
    const missingPaths = pathSet(join(cacheDir, "missing"));
    let missingCacheExecutions = 0;
    assert.strictEqual(validateCachedBinary(missingPaths.binaryPath, missingPaths.manifestPath, {
      execFileSyncImpl: () => { missingCacheExecutions += 1; },
    }), false, "a missing cache directory is a cache miss");
    assert.strictEqual(missingCacheExecutions, 0, "a missing cache must not execute a binary");
    assert.deepStrictEqual(readdirSync(cacheDir), [], "checking a missing cache must not create it");

    const paths = pathSet(cacheDir);
    assert.strictEqual(paths.lockPath, join(dirname(cacheDir), `.${basename(cacheDir)}.install.lock`));
    let emptyCacheExecutions = 0;
    assert.strictEqual(validateCachedBinary(paths.binaryPath, paths.manifestPath, {
      execFileSyncImpl: () => { emptyCacheExecutions += 1; },
    }), false, "an empty cache directory is a cache miss");
    assert.strictEqual(emptyCacheExecutions, 0, "a cache miss must not execute a binary");
    assert.deepStrictEqual(readdirSync(cacheDir), [], "checking the cache must not create artifacts");
    const contents = "known-valid-cache";
    writePrivateFile(paths.binaryPath, contents, 0o700);
    const sha256 = crypto.createHash("sha256").update(contents).digest("hex");
    writePrivateFile(
      paths.manifestPath,
      `${JSON.stringify({ version: candidateVersion, sha256 })}\n`,
      0o600
    );
    let executions = 0;
    const resolved = await ensureBinary({
      cacheDir,
      execFileSyncImpl: (observedPath, args) => {
        executions += 1;
        assert.strictEqual(observedPath, paths.binaryPath);
        assert.deepStrictEqual(args, ["--version"]);
        return Buffer.from(("phantom-mcp " + candidateVersion + "\n"));
      },
      downloadImpl: async () => {
        throw new Error("valid cache must not download");
      },
    });
    assert.strictEqual(resolved, paths.binaryPath);
    assert.strictEqual(executions, 1);
    assert.strictEqual(readFileSync(paths.binaryPath, "utf8"), contents);
    assert.strictEqual(readFileSync(paths.sourceMarkerPath, "utf8"), "npm\n");

    rmSync(paths.binaryPath);
    rmSync(paths.manifestPath);
    writePrivateFile(paths.binaryPath, "", 0o700);
    const emptySha256 = crypto.createHash("sha256").update("").digest("hex");
    writePrivateFile(paths.manifestPath, `${JSON.stringify({ version: candidateVersion, sha256: emptySha256 })}\n`, 0o600);
    const archive = Buffer.from("replacement-archive");
    const archiveSha256 = crypto.createHash("sha256").update(archive).digest("hex");
    const downloads = [];
    let cachedExecutions = 0;
    let candidateExecutions = 0;
    const replacement = await ensureBinary({
      cacheDir,
      downloadImpl: async (url) => {
        downloads.push(url);
        return url.endsWith(".sha256")
          ? Buffer.from(`${archiveSha256}  ${basename(url.slice(0, -7))}\n`)
          : archive;
      },
      extractImpl: (_archivePath, candidatePath) => {
        writePrivateFile(candidatePath, "replacement-binary", 0o700);
      },
      execFileSyncImpl: (observedPath, args) => {
        assert.deepStrictEqual(args, ["--version"]);
        if (observedPath === paths.binaryPath) {
          cachedExecutions += 1;
          throw new Error("empty binary cannot execute");
        }
        candidateExecutions += 1;
        return Buffer.from("phantom-mcp " + candidateVersion + "\n");
      },
    });
    assert.strictEqual(replacement, paths.binaryPath);
    assert.strictEqual(cachedExecutions, 1);
    assert.strictEqual(candidateExecutions, 1);
    assert.strictEqual(downloads.length, 2);
    assert.ok(downloads[0].endsWith(".sha256"));
    assert.strictEqual(downloads[1], downloads[0].slice(0, -7));
    assert.strictEqual(readFileSync(paths.binaryPath, "utf8"), "replacement-binary");
  } finally {
    rmSync(cacheDir, { recursive: true, force: true });
  }
  console.log("npm MCP wrapper validates manifest before executing cached binary");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
