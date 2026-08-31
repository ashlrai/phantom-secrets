const assert = require("assert");
const crypto = require("crypto");
const { execFileSync } = require("child_process");
const {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  truncateSync,
  unlinkSync,
  writeFileSync,
} = require("fs");
const { tmpdir } = require("os");
const { join, resolve } = require("path");

const verifier = resolve(__dirname, "..", "..", "scripts", "release", "verify-release-artifacts.mjs");
const archives = [
  "phantom-aarch64-apple-darwin.tar.gz",
  "phantom-x86_64-apple-darwin.tar.gz",
  "phantom-aarch64-unknown-linux-gnu.tar.gz",
  "phantom-x86_64-unknown-linux-gnu.tar.gz",
  "phantom-aarch64-pc-windows-msvc.zip",
  "phantom-x86_64-pc-windows-msvc.zip",
];
const maxArchiveBytes = 100 * 1024 * 1024;

function digest(path) {
  return crypto.createHash("sha256").update(readFileSync(path)).digest("hex");
}

function run(root) {
  return execFileSync(process.execPath, [verifier, root], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function writeIntegrity(root) {
  const aggregate = [];
  for (const [index, name] of archives.entries()) {
    const archive = join(root, `artifact-${index}`, name);
    const sha = digest(archive);
    writeFileSync(`${archive}.sha256`, `${sha}  ${name}\n`);
    aggregate.push(`${sha}  ${name}`);
  }
  writeFileSync(join(root, "SHA256SUMS"), `${aggregate.join("\n")}\n`);
  return aggregate;
}

function writeSbom(path, archiveName) {
  writeFileSync(path, `${JSON.stringify({
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: archiveName,
    documentNamespace: `https://phm.dev/sbom/${encodeURIComponent(archiveName)}`,
    creationInfo: {
      created: "2026-08-31T12:00:00Z",
      creators: ["Tool: syft-1.42.3"],
    },
    packages: [],
  }, null, 2)}\n`);
}

function createArchives(root, sourceRoot) {
  for (const [index, name] of archives.entries()) {
    const directory = join(root, `artifact-${index}`);
    const source = join(sourceRoot, `source-${index}`);
    mkdirSync(directory, { mode: 0o700 });
    mkdirSync(source, { mode: 0o700 });
    if (name.endsWith(".zip")) {
      writeFileSync(join(source, "phantom.exe"), "cli");
      writeFileSync(join(source, "phantom-mcp.exe"), "mcp");
      execFileSync("zip", ["-q", join(directory, name), "phantom.exe", "phantom-mcp.exe"], {
        cwd: source,
      });
    } else {
      writeFileSync(join(source, "phantom"), "cli");
      writeFileSync(join(source, "phantom-mcp"), "mcp");
      chmodSync(join(source, "phantom"), 0o755);
      chmodSync(join(source, "phantom-mcp"), 0o755);
      execFileSync("tar", ["-czf", join(directory, name), "-C", source, "phantom", "phantom-mcp"]);
    }
    writeSbom(join(directory, `${name}.spdx.json`), name);
  }
  return writeIntegrity(root);
}

const root = mkdtempSync(join(tmpdir(), "phantom-release-artifacts-"));
const sourceRoot = mkdtempSync(join(tmpdir(), "phantom-release-sources-"));
try {
  let aggregate = createArchives(root, sourceRoot);
  const aggregatePath = join(root, "SHA256SUMS");
  assert.match(run(root), /6 archives, 6 SBOMs, and 19 exact files/);

  const firstArchive = join(root, "artifact-0", archives[0]);
  const extraSource = join(sourceRoot, "extra-source");
  mkdirSync(extraSource, { mode: 0o700 });
  for (const name of ["phantom", "phantom-mcp", "unexpected"]) {
    writeFileSync(join(extraSource, name), name);
  }
  execFileSync("tar", [
    "-czf", firstArchive, "-C", extraSource, "phantom", "phantom-mcp", "unexpected",
  ]);
  aggregate = writeIntegrity(root);
  assert.throws(() => run(root), /must contain exactly phantom and phantom-mcp/);

  unlinkSync(firstArchive);
  writeFileSync(join(extraSource, "phantom"), "cli");
  unlinkSync(join(extraSource, "phantom-mcp"));
  symlinkSync("phantom", join(extraSource, "phantom-mcp"));
  execFileSync("tar", ["-czf", firstArchive, "-C", extraSource, "phantom", "phantom-mcp"]);
  aggregate = writeIntegrity(root);
  assert.throws(() => run(root), /members must be regular files/);

  unlinkSync(firstArchive);
  unlinkSync(join(extraSource, "phantom-mcp"));
  writeFileSync(join(extraSource, "phantom-mcp"), "mcp");
  execFileSync("tar", ["-czf", firstArchive, "-C", extraSource, "phantom", "phantom-mcp"]);
  aggregate = writeIntegrity(root);
  assert.match(run(root), /6 archives/);

  truncateSync(firstArchive, maxArchiveBytes + 1);
  assert.throws(() => run(root), /must be between 1 byte and 100 MiB/);
  unlinkSync(firstArchive);
  execFileSync("tar", ["-czf", firstArchive, "-C", extraSource, "phantom", "phantom-mcp"]);
  aggregate = writeIntegrity(root);

  const unexpected = join(root, "unexpected.txt");
  writeFileSync(unexpected, "unexpected");
  assert.throws(() => run(root), /unexpected release artifact files/);
  unlinkSync(unexpected);

  const firstSbom = join(root, "artifact-0", `${archives[0]}.spdx.json`);
  const validSbom = readFileSync(firstSbom, "utf8");
  unlinkSync(firstSbom);
  assert.throws(() => run(root), /exactly 19 release files/);
  writeFileSync(firstSbom, "not-json\n");
  assert.throws(() => run(root), /is not valid JSON/);
  writeFileSync(firstSbom, validSbom.replace('"SPDX-2.3"', '"SPDX-2.2"'));
  assert.throws(() => run(root), /must declare SPDX-2.3 and CC0-1.0/);
  writeFileSync(firstSbom, validSbom.replace(archives[0], archives[1]));
  assert.throws(() => run(root), /wrong document identity/);
  writeFileSync(firstSbom, validSbom);

  const extraSbom = join(root, "unexpected.spdx.json");
  writeSbom(extraSbom, "unexpected.tar.gz");
  assert.throws(() => run(root), /unexpected release artifact files/);
  unlinkSync(extraSbom);

  const firstSidecar = `${firstArchive}.sha256`;
  unlinkSync(firstSidecar);
  assert.throws(() => run(root), /exactly 19 release files/);
  writeFileSync(firstSidecar, `${aggregate[0]}\n`);

  writeFileSync(firstSidecar, `${"0".repeat(64)}  ${archives[0]}\n`);
  assert.throws(() => run(root), /checksum mismatch/);
  writeFileSync(firstSidecar, `${aggregate[0]}\n`);

  writeFileSync(aggregatePath, `${aggregate.slice(0, -1).join("\n")}\n${aggregate[0]}\n`);
  assert.throws(() => run(root), /unexpected or duplicate entry/);
  writeIntegrity(root);

  const duplicateDir = join(root, "duplicate");
  mkdirSync(duplicateDir, { mode: 0o700 });
  writeFileSync(join(duplicateDir, archives[0]), "duplicate");
  assert.throws(() => run(root), /exactly 19 release files/);
} finally {
  rmSync(root, { recursive: true, force: true });
  rmSync(sourceRoot, { recursive: true, force: true });
}

console.log("release artifact verifier enforces exact archives, SBOMs, checksums, members, and regular types");
