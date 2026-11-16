// One proof for both wrappers. The packages cannot share a published helper,
// so this file drives each wrapper's own ensureBinary instead of copying the
// cases into both suites.
const assert = require("assert");
const crypto = require("crypto");
const { existsSync, readFileSync, rmSync, symlinkSync } = require("fs");
const { tmpdir } = require("os");
const { basename, join } = require("path");

const cli = require("../bin/cli.js");
const mcp = require("../../npm-mcp/bin/cli.js");

const wrappers = [
  {
    label: "npm-cli",
    wrapper: cli,
    version: require("../package.json").version,
    binaryName: "phantom",
    markerName: ".phantom-install-source.npm-cli",
    invalidMarker: /invalid npm-cli install-source marker/,
  },
  {
    label: "npm-mcp",
    wrapper: mcp,
    version: require("../../npm-mcp/package.json").version,
    binaryName: "phantom-mcp",
    markerName: ".phantom-install-source.npm-mcp",
    invalidMarker: /invalid npm-mcp install-source marker/,
  },
];

async function proveMarkerFollowsValidation(spec) {
  const cacheDir = join(tmpdir(), `phantom-source-marker-${spec.label}-${process.pid}`);
  rmSync(cacheDir, { recursive: true, force: true });
  spec.wrapper.ensurePrivateCacheDir(cacheDir);
  try {
    const paths = spec.wrapper.pathSet(cacheDir);
    assert.strictEqual(basename(paths.sourceMarkerPath), spec.markerName, spec.label);
    const binary = Buffer.from(`known-valid-${spec.label}`);
    const sha256 = crypto.createHash("sha256").update(binary).digest("hex");
    spec.wrapper.writePrivateFile(paths.binaryPath, binary, 0o700);
    spec.wrapper.writePrivateFile(
      paths.manifestPath,
      `${JSON.stringify({ version: spec.version, sha256 })}\n`,
      0o600
    );

    let markerDuringCheck = null;
    const adopted = await spec.wrapper.ensureBinary({
      cacheDir,
      execFileSyncImpl: () => {
        markerDuringCheck = existsSync(paths.sourceMarkerPath);
        return Buffer.from(`${spec.binaryName} ${spec.version}\n`);
      },
      downloadImpl: async () => {
        throw new Error(`${spec.label} valid cache must not download`);
      },
    });
    assert.strictEqual(adopted, paths.binaryPath, spec.label);
    assert.strictEqual(markerDuringCheck, false, `${spec.label} marker waits until validation succeeds`);
    assert.strictEqual(readFileSync(paths.sourceMarkerPath, "utf8"), "npm\n", `${spec.label} success writes the marker`);

    rmSync(paths.sourceMarkerPath);
    const retryFailure = new Error(`${spec.label} synthetic retry download failure`);
    await assert.rejects(spec.wrapper.ensureBinary({
      cacheDir,
      execFileSyncImpl: () => Buffer.from(`${spec.binaryName} 0.5.0\n`),
      downloadImpl: async () => { throw retryFailure; },
    }), (error) => error === retryFailure);
    assert.strictEqual(existsSync(paths.sourceMarkerPath), false, `${spec.label} failed validation leaves no marker`);
    assert.deepStrictEqual(readFileSync(paths.binaryPath), binary, spec.label);

    for (const markerKind of process.platform === "win32" ? ["invalid"] : ["invalid", "symlink"]) {
      const unsafeCache = join(cacheDir, `unsafe-${markerKind}`);
      spec.wrapper.ensurePrivateCacheDir(unsafeCache);
      const unsafePaths = spec.wrapper.pathSet(unsafeCache);
      const sentinel = join(unsafeCache, "sentinel");
      spec.wrapper.writePrivateFile(sentinel, "npm\n", 0o600);
      if (markerKind === "symlink") symlinkSync(sentinel, unsafePaths.sourceMarkerPath);
      else spec.wrapper.writePrivateFile(unsafePaths.sourceMarkerPath, "invalid\n", 0o600);
      let operations = 0;
      await assert.rejects(spec.wrapper.ensureBinary({
        cacheDir: unsafeCache,
        execFileSyncImpl: () => { operations += 1; },
        downloadImpl: async () => { operations += 1; },
      }), markerKind === "symlink" ? /symbolic link/ : spec.invalidMarker);
      assert.strictEqual(operations, 0, `${spec.label} ${markerKind} marker fails before execution or download`);
      assert.strictEqual(readFileSync(sentinel, "utf8"), "npm\n");
      assert.strictEqual(existsSync(unsafePaths.binaryPath), false);
      assert.strictEqual(existsSync(unsafePaths.lockPath), false);
    }
  } finally {
    rmSync(cacheDir, { recursive: true, force: true });
  }
}

(async () => {
  for (const spec of wrappers) await proveMarkerFollowsValidation(spec);
  console.log("npm ownership markers are written only after binary validation");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
