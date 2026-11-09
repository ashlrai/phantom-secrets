// Fixtures follow the independent package carrier, not the wrapper implementation.
const candidateVersion = require("../package.json").version;
const assert = require("assert");
const crypto = require("crypto");
const http = require("http");
const https = require("https");
const { mkdtempSync, readFileSync, rmSync } = require("fs");
const { tmpdir } = require("os");
const { basename, dirname, join } = require("path");

const { ensureBinary, pathSet, validateCachedBinary, writePrivateFile } = require("../bin/cli.js");

(async () => {
  const cacheDir = mkdtempSync(join(tmpdir(), "phantom-mcp-valid-cache-"));
  try {
    const paths = pathSet(cacheDir);
    assert.strictEqual(paths.lockPath, join(dirname(cacheDir), `.${basename(cacheDir)}.install.lock`));
    // An empty cache is invalid and validation must remain entirely local.
    const originals = [http.request, http.get, https.request, https.get];
    let networkRequests = 0;
    let missingExecutions = 0;
    const rejectNetwork = () => { networkRequests += 1; throw new Error("unexpected network request"); };
    try {
      http.request = http.get = https.request = https.get = rejectNetwork;
      assert.strictEqual(validateCachedBinary(paths.binaryPath, paths.manifestPath, {
        execFileSyncImpl: () => { missingExecutions += 1; },
      }), false);
      assert.strictEqual(missingExecutions, 0, "missing binary must not execute");
      assert.strictEqual(networkRequests, 0, "cache validation must not use the network");
    } finally {
      [http.request, http.get, https.request, https.get] = originals;
    }
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
  } finally {
    rmSync(cacheDir, { recursive: true, force: true });
  }
  console.log("npm MCP wrapper validates manifest before executing cached binary");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
