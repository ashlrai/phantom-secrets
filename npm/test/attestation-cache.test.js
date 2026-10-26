const assert = require("assert");
const crypto = require("crypto");
const {
  chmodSync, lstatSync, mkdtempSync, readFileSync, renameSync, rmSync,
  statSync, symlinkSync, utimesSync, writeFileSync,
} = require("fs");
const { tmpdir } = require("os");
const { join } = require("path");

const {
  attestationPath, ensurePrivateCacheDir, pathSet, readVerifiedManifest,
  validateCachedBinary, writePrivateFile,
} = require("../bin/cli.js");

const okVersion = () => Buffer.from("phantom 0.7.9\n");
const noSpawn = () => { throw new Error("must not spawn"); };

function writePair(paths, contents) {
  writePrivateFile(paths.binaryPath, contents, 0o700);
  const sha256 = crypto.createHash("sha256").update(contents).digest("hex");
  writePrivateFile(paths.manifestPath, `${JSON.stringify({ version: "0.7.9", sha256 })}\n`, 0o600);
  return sha256;
}

function identity(path) {
  const s = lstatSync(path, { bigint: true });
  return { dev: `${s.dev}`, ino: `${s.ino}`, size: `${s.size}`, mtimeNs: `${s.mtimeNs}`, ctimeNs: `${s.ctimeNs}` };
}

// Forge an attestation for the binary as it is now. With secure permissions it
// would be trusted (same-user writers are out of scope, see the manifest note),
// so each refusal case below proves the forged record is ignored and the full
// hash then rejects the tampered binary.
function forge(paths, sha256, mode = 0o600) {
  const record = { schema: 1, version: "0.7.9", sha256, versionChecked: true, identity: identity(paths.binaryPath) };
  writePrivateFile(attestationPath(paths.binaryPath), `${JSON.stringify(record)}\n`, 0o600);
  if (mode !== 0o600) chmodSync(attestationPath(paths.binaryPath), mode);
}

if (process.platform === "win32") {
  console.log("attestation cache tests skipped on win32 (POSIX permission cases)");
  process.exit(0);
}

const dir = mkdtempSync(join(tmpdir(), "phantom-attest-test-"));
try {
  ensurePrivateCacheDir(dir);
  const paths = pathSet(dir);
  const att = attestationPath(paths.binaryPath);

  // Cache hit: first call hashes and spawns once, then the attested call does neither spawn nor fail.
  const sha = writePair(paths, "AAAAAAAAAAAAAAAA");
  let spawns = 0;
  assert.strictEqual(validateCachedBinary(paths.binaryPath, paths.manifestPath, {
    execFileSyncImpl: () => { spawns += 1; return okVersion(); },
  }), true);
  assert.strictEqual(spawns, 1);
  assert.strictEqual(statSync(att).mode & 0o777, 0o600, "attestation must be 0600");
  assert.strictEqual(validateCachedBinary(paths.binaryPath, paths.manifestPath, { execFileSyncImpl: noSpawn }), true);

  // Same-size swap by rename-over: new inode and ctime, key misses, full hash catches it.
  const swap = join(dir, "swap");
  writePrivateFile(swap, "BBBBBBBBBBBBBBBB", 0o700);
  renameSync(swap, paths.binaryPath);
  assert.strictEqual(readVerifiedManifest(paths.binaryPath, paths.manifestPath), null);
  assert.strictEqual(validateCachedBinary(paths.binaryPath, paths.manifestPath, { execFileSyncImpl: noSpawn }), false);

  // Same-size in-place rewrite with mtime restored: same inode, ctime changes, still caught.
  rmSync(paths.binaryPath); rmSync(paths.manifestPath);
  writePair(paths, "CCCCCCCCCCCCCCCC");
  assert.strictEqual(validateCachedBinary(paths.binaryPath, paths.manifestPath, { execFileSyncImpl: okVersion }), true);
  const before = lstatSync(paths.binaryPath);
  const inoBefore = before.ino;
  writeFileSync(paths.binaryPath, "DDDDDDDDDDDDDDDD");
  utimesSync(paths.binaryPath, before.atime, before.mtime);
  assert.strictEqual(lstatSync(paths.binaryPath).ino, inoBefore, "in-place rewrite keeps the inode");
  assert.strictEqual(readVerifiedManifest(paths.binaryPath, paths.manifestPath), null);

  // Forged attestations for the tampered binary (contents no longer match sha).
  const cSha = crypto.createHash("sha256").update("CCCCCCCCCCCCCCCC").digest("hex");
  const refused = (label) => {
    assert.strictEqual(readVerifiedManifest(paths.binaryPath, paths.manifestPath), null, label);
    assert.strictEqual(validateCachedBinary(paths.binaryPath, paths.manifestPath, { execFileSyncImpl: noSpawn }), false, label);
  };
  rmSync(att, { force: true });
  forge(paths, cSha);
  assert.ok(readVerifiedManifest(paths.binaryPath, paths.manifestPath), "control: a secure, matching forged record is trusted");
  rmSync(att);
  for (const mode of [0o644, 0o620, 0o602, 0o666]) {
    forge(paths, cSha, mode);
    refused(`insecure attestation mode ${mode.toString(8)}`);
    rmSync(att, { force: true });
  }

  forge(paths, cSha);
  chmodSync(dir, 0o770);
  refused("group-writable cache dir");
  chmodSync(dir, 0o700);
  rmSync(att, { force: true });

  const target = join(dir, "real-attestation");
  forge(paths, cSha);
  renameSync(att, target);
  symlinkSync(target, att);
  refused("symlinked attestation");
  rmSync(att, { force: true }); rmSync(target, { force: true });

  writePrivateFile(att, "{not json", 0o600);
  refused("corrupt attestation");
  rmSync(att, { force: true });

  for (const mutate of [
    (r) => { r.sha256 = sha; },
    (r) => { r.version = "0.7.8"; },
    (r) => { r.identity.ctimeNs = "1"; },
    (r) => { r.extra = true; },
  ]) {
    forge(paths, cSha);
    const record = JSON.parse(readFileSync(att, "utf8"));
    mutate(record);
    rmSync(att);
    writePrivateFile(att, JSON.stringify(record), 0o600);
    refused("mismatched attestation fields");
    rmSync(att, { force: true });
  }

  // Changed expectation: a new manifest digest invalidates an existing attestation.
  rmSync(paths.binaryPath); rmSync(paths.manifestPath);
  writePair(paths, "EEEEEEEEEEEEEEEE");
  assert.strictEqual(validateCachedBinary(paths.binaryPath, paths.manifestPath, { execFileSyncImpl: okVersion }), true);
  rmSync(paths.manifestPath);
  writePrivateFile(paths.manifestPath, `${JSON.stringify({ version: "0.7.9", sha256: "f".repeat(64) })}\n`, 0o600);
  assert.strictEqual(readVerifiedManifest(paths.binaryPath, paths.manifestPath), null);
} finally {
  chmodSync(dir, 0o700);
  rmSync(dir, { recursive: true, force: true });
}
console.log("npm CLI wrapper attestation cache tests passed");
