const assert = require("assert");
const crypto = require("crypto");
const { mkdtempSync, readFileSync, rmSync } = require("fs");
const { tmpdir } = require("os");
const { join } = require("path");

const { ensureBinary, pathSet, writePrivateFile } = require("../bin/cli.js");

(async () => {
  const cacheDir = mkdtempSync(join(tmpdir(), "phantom-mcp-valid-cache-"));
  try {
    const paths = pathSet(cacheDir);
    const contents = "known-valid-cache";
    writePrivateFile(paths.binaryPath, contents, 0o700);
    const sha256 = crypto.createHash("sha256").update(contents).digest("hex");
    writePrivateFile(
      paths.manifestPath,
      `${JSON.stringify({ version: "0.7.0", sha256 })}\n`,
      0o600
    );
    let executions = 0;
    const resolved = await ensureBinary({
      cacheDir,
      execFileSyncImpl: (observedPath, args) => {
        executions += 1;
        assert.strictEqual(observedPath, paths.binaryPath);
        assert.deepStrictEqual(args, ["--version"]);
        return Buffer.from("phantom-mcp 0.7.0\n");
      },
      downloadImpl: async () => {
        throw new Error("valid cache must not download");
      },
    });
    assert.strictEqual(resolved, paths.binaryPath);
    assert.strictEqual(executions, 1);
    assert.strictEqual(readFileSync(paths.binaryPath, "utf8"), contents);
  } finally {
    rmSync(cacheDir, { recursive: true, force: true });
  }
  console.log("npm MCP wrapper validates manifest before executing cached binary");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
