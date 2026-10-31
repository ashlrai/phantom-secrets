const assert = require("assert");
const crypto = require("crypto");
const { existsSync, lstatSync, mkdtempSync, readFileSync, readdirSync, rmSync } = require("fs");
const { tmpdir } = require("os");
const { basename, dirname, join } = require("path");

const { ensureBinary, getPlatformTarget, pathSet, writePrivateFile } = require("../bin/cli.js");

(async () => {
  const cacheDir = mkdtempSync(join(tmpdir(), "phantom-cli-valid-cache-"));
  try {
    const paths = pathSet(cacheDir);
    assert.strictEqual(paths.lockPath, join(dirname(cacheDir), `.${basename(cacheDir)}.install.lock`));
    const contents = "known-valid-cache";
    writePrivateFile(paths.binaryPath, contents, 0o700);
    const sha256 = crypto.createHash("sha256").update(contents).digest("hex");
    writePrivateFile(
      paths.manifestPath,
      `${JSON.stringify({ version: "0.8.0", sha256 })}\n`,
      0o600
    );
    let executions = 0;
    const resolved = await ensureBinary({
      cacheDir,
      execFileSyncImpl: (observedPath, args) => {
        executions += 1;
        assert.strictEqual(observedPath, paths.binaryPath);
        assert.deepStrictEqual(args, ["--version"]);
        return Buffer.from("phantom 0.8.0\n");
      },
      downloadImpl: async () => {
        throw new Error("valid cache must not download");
      },
    });
    assert.strictEqual(resolved, paths.binaryPath);
    assert.strictEqual(executions, 1);
    assert.strictEqual(readFileSync(paths.binaryPath, "utf8"), contents);
    assert.strictEqual(readFileSync(paths.sourceMarkerPath, "utf8"), "npm\n");
  } finally {
    rmSync(cacheDir, { recursive: true, force: true });
  }

  const fixtureDir = mkdtempSync(join(tmpdir(), "phantom-cli-missing-cache-"));
  try {
    const missingCacheDir = join(fixtureDir, "missing-parent", "bin");
    const paths = pathSet(missingCacheDir);
    const target = getPlatformTarget(process);
    const archiveName = `phantom-${target}.${process.platform === "win32" ? "zip" : "tar.gz"}`;
    const archiveUrl = `https://github.com/ashlrai/phantom-secrets/releases/download/v0.8.0/${archiveName}`;
    const archive = Buffer.from("verified archive fixture");
    const binary = Buffer.from("installed binary fixture");
    const archiveHash = crypto.createHash("sha256").update(archive).digest("hex");
    const binaryHash = crypto.createHash("sha256").update(binary).digest("hex");
    const downloads = [];
    let extractions = 0;
    let executions = 0;

    assert.strictEqual(existsSync(missingCacheDir), false);
    const options = {
      cacheDir: missingCacheDir,
      downloadImpl: async (url) => {
        downloads.push(url);
        assert.ok(lstatSync(missingCacheDir).isDirectory());
        if (url === `${archiveUrl}.sha256`) return Buffer.from(`${archiveHash}  ${archiveName}\n`);
        assert.strictEqual(url, archiveUrl);
        return archive;
      },
      extractImpl: (archivePath, candidatePath) => {
        extractions += 1;
        assert.deepStrictEqual(readFileSync(archivePath), archive);
        writePrivateFile(candidatePath, binary, 0o700);
      },
      execFileSyncImpl: (observedPath, args) => {
        executions += 1;
        assert.deepStrictEqual(args, ["--version"]);
        assert.deepStrictEqual(readFileSync(observedPath), binary);
        return Buffer.from("phantom 0.8.0\n");
      },
    };

    assert.strictEqual(await ensureBinary(options), paths.binaryPath);
    assert.deepStrictEqual(downloads, [`${archiveUrl}.sha256`, archiveUrl]);
    assert.strictEqual(extractions, 1);
    assert.strictEqual(executions, 1);
    assert.deepStrictEqual(readFileSync(paths.binaryPath), binary);
    assert.deepStrictEqual(JSON.parse(readFileSync(paths.manifestPath, "utf8")), {
      version: "0.8.0",
      sha256: binaryHash,
    });
    assert.strictEqual(readFileSync(paths.sourceMarkerPath, "utf8"), "npm\n");
    if (process.platform !== "win32") assert.strictEqual(lstatSync(missingCacheDir).mode & 0o777, 0o700);
    assert.strictEqual(existsSync(paths.lockPath), false);
    assert.strictEqual(existsSync(paths.transactionPath), false);
    assert.ok(readdirSync(missingCacheDir).every((name) => !name.startsWith(".install-")));

    assert.strictEqual(await ensureBinary(options), paths.binaryPath);
    assert.strictEqual(downloads.length, 2, "installed binary must be reused without downloading");
    assert.strictEqual(extractions, 1);
    assert.strictEqual(executions, 2);
  } finally {
    rmSync(fixtureDir, { recursive: true, force: true });
  }
  console.log("npm CLI wrapper validates manifest before executing cached binary");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
