import assert from "node:assert/strict";
import {
  appendFileSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

import {
  NATIVE_TARGETS,
  runNativeReleaseSmoke,
  validateNativeRuntime,
} from "./native-release-smoke.mjs";

const repoRoot = resolve(import.meta.dirname, "../..");
const workflow = readFileSync(
  resolve(repoRoot, ".github/workflows/release-build.yml"),
  "utf8",
);
const releaseWorkflow = readFileSync(
  resolve(repoRoot, ".github/workflows/release.yml"),
  "utf8",
);
const platformSupport = readFileSync(resolve(repoRoot, "docs/platform-support.md"), "utf8");
const fixtureTarget = "x86_64-unknown-linux-gnu";
const fixtureEnv = Object.freeze({ RUNNER_OS: "Linux", RUNNER_ARCH: "X64" });
const fixtureRuntime = Object.freeze({ platform: "linux", arch: "x64" });

const expected = Object.freeze({
  "x86_64-apple-darwin": [
    "phantom-x86_64-apple-darwin",
    "phantom-x86_64-apple-darwin.tar.gz",
    "macos-15-intel",
    "macOS",
    "X64",
  ],
  "aarch64-apple-darwin": [
    "phantom-aarch64-apple-darwin",
    "phantom-aarch64-apple-darwin.tar.gz",
    "macos-15",
    "macOS",
    "ARM64",
  ],
  "x86_64-unknown-linux-gnu": [
    "phantom-x86_64-unknown-linux-gnu",
    "phantom-x86_64-unknown-linux-gnu.tar.gz",
    "ubuntu-22.04",
    "Linux",
    "X64",
  ],
  "aarch64-unknown-linux-gnu": [
    "phantom-aarch64-unknown-linux-gnu",
    "phantom-aarch64-unknown-linux-gnu.tar.gz",
    "ubuntu-22.04-arm",
    "Linux",
    "ARM64",
  ],
  "x86_64-pc-windows-msvc": [
    "phantom-x86_64-pc-windows-msvc",
    "phantom-x86_64-pc-windows-msvc.zip",
    "windows-latest",
    "Windows",
    "X64",
  ],
  "aarch64-pc-windows-msvc": [
    "phantom-aarch64-pc-windows-msvc",
    "phantom-aarch64-pc-windows-msvc.zip",
    "windows-11-vs2026-arm",
    "Windows",
    "ARM64",
  ],
});

function job(source, name, next) {
  const start = source.indexOf(`\n  ${name}:\n`);
  assert.notEqual(start, -1, `missing ${name} job`);
  if (!next) return source.slice(start);
  const end = source.indexOf(`\n  ${next}:\n`, start + 1);
  assert.notEqual(end, -1, `missing ${next} job after ${name}`);
  return source.slice(start, end);
}

function matrixRows(jobText) {
  const rows = new Map();
  const matches = [...jobText.matchAll(/^          - target: ([^\s]+)\n([\s\S]*?)(?=^          - target: |^    steps:)/gm)];
  for (const match of matches) {
    const fields = new Map(
      [...match[2].matchAll(/^            ([a-z_]+): ([^\n]+)$/gm)].map((field) => [field[1], field[2]]),
    );
    rows.set(match[1], fields);
  }
  return rows;
}

function lines(values) {
  return `${values.join("\n")}\n`;
}

function nativeArchiveFixture(t, options = {}) {
  const contract = NATIVE_TARGETS[fixtureTarget];
  const directory = mkdtempSync(join(tmpdir(), "phantom-native-smoke-test-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const archivePath = join(directory, contract.archive);
  writeFileSync(archivePath, "synthetic immutable archive");
  writeFileSync(`${archivePath}.spdx.json`, "{}\n");

  const expectedMembers = [...contract.binaries];
  const members = options.members ?? expectedMembers;
  const verboseMembers =
    options.verboseMembers ??
    expectedMembers.map((name) => `-rwxr-xr-x 0 0 0 1 Jan 1 00:00 ${name}`);
  const commands = [];
  let extractionDirectory;

  function runCommand(command, args, label) {
    commands.push({ command, args: [...args], label });
    if (label === `inspect ${contract.archive}`) {
      assert.equal(command, "tar");
      return lines(members);
    }
    if (label === `inspect types in ${contract.archive}`) {
      assert.equal(command, "tar");
      return lines(verboseMembers);
    }
    if (label === `extract ${contract.archive}`) {
      assert.equal(command, "tar");
      const destinationIndex = args.indexOf("-C");
      assert.notEqual(destinationIndex, -1, "extract command must select a destination");
      extractionDirectory = args[destinationIndex + 1];
      for (const name of expectedMembers) {
        writeFileSync(join(extractionDirectory, name), "synthetic executable\n", { mode: 0o755 });
      }
      if (options.extractedExtra) {
        writeFileSync(join(extractionDirectory, options.extractedExtra), "unexpected\n");
      }
      if (options.mutateArchive) appendFileSync(archivePath, "mutated");
      return "";
    }
    if (label === "phantom --version") {
      return `${options.phantomVersion ?? "phantom 0.7.7"}\n`;
    }
    if (label === "phantom-mcp --version") {
      return `${options.phantomMcpVersion ?? "phantom-mcp 0.7.7"}\n`;
    }
    if (label === "MCP stdio schema smoke") {
      if (options.failMcp) throw new Error("synthetic MCP schema failure");
      return "";
    }
    throw new Error(`unexpected synthetic command: ${label}`);
  }

  return {
    archivePath,
    commands,
    extractionDirectory: () => extractionDirectory,
    smoke: () =>
      runNativeReleaseSmoke({
        archivePath,
        target: fixtureTarget,
        tag: "v0.7.7",
        env: fixtureEnv,
        runtime: fixtureRuntime,
        runCommand,
      }),
  };
}

test("native target contract is closed, unique, and exact", () => {
  assert.deepEqual(Object.keys(NATIVE_TARGETS).sort(), Object.keys(expected).sort());
  const artifacts = new Set();
  const archives = new Set();
  for (const [target, values] of Object.entries(expected)) {
    const [artifact, archive, runner, runnerOs, runnerArch] = values;
    const contract = NATIVE_TARGETS[target];
    assert.deepEqual(
      [contract.artifact, contract.archive, contract.runner, contract.runnerOs, contract.runnerArch],
      [artifact, archive, runner, runnerOs, runnerArch],
    );
    assert(!artifacts.has(artifact), `duplicate artifact ${artifact}`);
    assert(!archives.has(archive), `duplicate archive ${archive}`);
    artifacts.add(artifact);
    archives.add(archive);
  }
});

test("runtime identity fails closed for unset, cross-OS, and cross-architecture runners", () => {
  const target = "aarch64-unknown-linux-gnu";
  assert.equal(
    validateNativeRuntime(
      target,
      { RUNNER_OS: "Linux", RUNNER_ARCH: "ARM64" },
      { platform: "linux", arch: "arm64" },
    ).runner,
    "ubuntu-22.04-arm",
  );
  assert.throws(
    () => validateNativeRuntime(target, {}, { platform: "linux", arch: "arm64" }),
    /runner mismatch/,
  );
  assert.throws(
    () =>
      validateNativeRuntime(
        target,
        { RUNNER_OS: "Linux", RUNNER_ARCH: "X64" },
        { platform: "linux", arch: "arm64" },
      ),
    /runner mismatch/,
  );
  assert.throws(
    () =>
      validateNativeRuntime(
        target,
        { RUNNER_OS: "Linux", RUNNER_ARCH: "ARM64" },
        { platform: "linux", arch: "x64" },
      ),
    /Node runtime mismatch/,
  );
});

test("native archive smoke exercises the complete accepted artifact path", (t) => {
  const fixture = nativeArchiveFixture(t);
  assert.deepEqual(fixture.smoke(), {
    archive: "phantom-x86_64-unknown-linux-gnu.tar.gz",
    target: fixtureTarget,
    version: "0.7.7",
  });
  assert.deepEqual(
    fixture.commands.map(({ label }) => label),
    [
      "inspect phantom-x86_64-unknown-linux-gnu.tar.gz",
      "inspect types in phantom-x86_64-unknown-linux-gnu.tar.gz",
      "extract phantom-x86_64-unknown-linux-gnu.tar.gz",
      "phantom --version",
      "phantom-mcp --version",
      "MCP stdio schema smoke",
    ],
  );
  assert.equal(
    existsSync(fixture.extractionDirectory()),
    false,
    "temporary extraction must be removed",
  );
});

test("native archive smoke rejects extra and traversal members before extraction", async (t) => {
  await t.test("extra member", (t) => {
    const fixture = nativeArchiveFixture(t, {
      members: ["phantom", "phantom-mcp", "README.md"],
    });
    assert.throws(fixture.smoke, /must contain exactly phantom, phantom-mcp/);
    assert.deepEqual(
      fixture.commands.map(({ label }) => label),
      ["inspect phantom-x86_64-unknown-linux-gnu.tar.gz"],
    );
  });

  await t.test("traversal member", (t) => {
    const fixture = nativeArchiveFixture(t, {
      members: ["phantom", "../phantom-mcp"],
    });
    assert.throws(fixture.smoke, /\.\.\/phantom-mcp/);
    assert.deepEqual(
      fixture.commands.map(({ label }) => label),
      ["inspect phantom-x86_64-unknown-linux-gnu.tar.gz"],
    );
  });
});

test("native archive smoke rejects non-regular members before extraction", (t) => {
  const fixture = nativeArchiveFixture(t, {
    verboseMembers: [
      "-rwxr-xr-x 0 0 0 1 Jan 1 00:00 phantom",
      "lrwxr-xr-x 0 0 0 0 Jan 1 00:00 phantom-mcp -> elsewhere",
    ],
  });
  assert.throws(fixture.smoke, /members must each be one regular file/);
  assert.deepEqual(
    fixture.commands.map(({ label }) => label),
    [
      "inspect phantom-x86_64-unknown-linux-gnu.tar.gz",
      "inspect types in phantom-x86_64-unknown-linux-gnu.tar.gz",
    ],
  );
});

test("native archive smoke rejects mutation during extraction", (t) => {
  const fixture = nativeArchiveFixture(t, { mutateArchive: true });
  assert.throws(fixture.smoke, /changed during extraction/);
  assert.equal(
    existsSync(fixture.extractionDirectory()),
    false,
    "failed extraction must be removed",
  );
});

test("native archive smoke rejects unexpected extracted files", (t) => {
  const fixture = nativeArchiveFixture(t, { extractedExtra: "unexpected" });
  assert.throws(fixture.smoke, /extracted archive contains unexpected entries/);
  assert.equal(
    existsSync(fixture.extractionDirectory()),
    false,
    "failed extraction must be removed",
  );
});

test("native archive smoke rejects a binary built at the wrong version", (t) => {
  const fixture = nativeArchiveFixture(t, { phantomVersion: "phantom 0.7.3" });
  assert.throws(
    fixture.smoke,
    /phantom --version must equal phantom 0\.7\.7; got phantom 0\.7\.3/,
  );
  assert.doesNotMatch(
    fixture.commands.map(({ label }) => label).join("\n"),
    /MCP stdio schema smoke/,
  );
});

test("native archive smoke propagates MCP schema failure after exact versions pass", (t) => {
  const fixture = nativeArchiveFixture(t, { failMcp: true });
  assert.throws(fixture.smoke, /synthetic MCP schema failure/);
  assert.equal(fixture.commands.at(-1).label, "MCP stdio schema smoke");
  assert.equal(
    existsSync(fixture.extractionDirectory()),
    false,
    "failed MCP smoke must clean up",
  );
});

test("release workflow binds every exact artifact to one native runner", () => {
  const nativeJob = job(workflow, "native-acceptance", "verify-artifacts");
  assert.match(nativeJob, /\n    needs: build\n/);
  assert.match(nativeJob, /\n    runs-on: \$\{\{ matrix\.os \}\}\n/);
  assert.match(nativeJob, /actions\/download-artifact@[0-9a-f]{40}/);
  assert.match(nativeJob, /name: \$\{\{ matrix\.artifact \}\}/);
  assert.match(nativeJob, /native-release-smoke\.mjs/);
  assert.match(nativeJob, /PHANTOM_NATIVE_ARCHIVE: native-artifact\/\$\{\{ matrix\.archive \}\}/);
  assert.match(nativeJob, /PHANTOM_NATIVE_TARGET: \$\{\{ matrix\.target \}\}/);
  assert.match(nativeJob, /PHANTOM_RELEASE_TAG: \$\{\{ inputs\.release_tag \}\}/);

  const rows = matrixRows(nativeJob);
  assert.deepEqual([...rows.keys()].sort(), Object.keys(expected).sort());
  const buildRows = matrixRows(job(workflow, "build", "native-acceptance"));
  assert.deepEqual([...buildRows.keys()].sort(), Object.keys(expected).sort());
  for (const [target, values] of Object.entries(expected)) {
    const [artifact, archive, runner, runnerOs, runnerArch] = values;
    assert.deepEqual(Object.fromEntries(rows.get(target)), {
      os: runner,
      artifact,
      archive,
      runner_os: runnerOs,
      runner_arch: runnerArch,
    });
    assert.equal(buildRows.get(target).get("artifact"), artifact);
    assert.equal(buildRows.get(target).get("archive"), archive);
  }
});

test("every native release runner exercises both npm wrappers without publication authority", () => {
  const native = job(workflow, "native-acceptance", "verify-artifacts");
  assert.match(native, /Exercise npm wrappers on the native filesystem/);
  for (const command of [
    "node npm/test/platform-matrix.test.js",
    "node npm/test/version-cache.test.js",
    "node npm/test/valid-cache.test.js",
    "node npm/test/hardening.test.js",
    "node npm-mcp/test/platform-matrix.test.js",
    "node npm-mcp/test/version-cache.test.js",
    "node npm-mcp/test/valid-cache.test.js",
    "node npm-mcp/test/hardening.test.js",
    "node npm-mcp/test/schema-contract.test.js",
  ]) {
    assert.match(native, new RegExp(command.replaceAll(".", "\\.")));
  }
  assert.doesNotMatch(native, /(?:npm|cargo|mcp-publisher) publish|gh release/);
});

test("attestation cannot begin before every build and native acceptance succeeds", () => {
  const verificationJob = job(workflow, "verify-artifacts");
  const attestJob = job(releaseWorkflow, "attest", "release");
  assert.match(verificationJob, /\n    needs: \[build, native-acceptance\]\n/);
  assert.match(attestJob, /\n    needs: build-and-verify\n/);
  assert.match(
    releaseWorkflow,
    /build-and-verify:\n(?:.|\n)*?uses: \.\/\.github\/workflows\/release-build\.yml/m,
  );
  assert.doesNotMatch(verificationJob, /continue-on-error:/);
  assert.doesNotMatch(attestJob, /continue-on-error:/);
  assert.doesNotMatch(
    job(workflow, "native-acceptance", "verify-artifacts"),
    /continue-on-error:/,
  );
});

test("platform documentation binds the immutable release receipt to every native row", () => {
  for (const [target, values] of Object.entries(expected)) {
    const [, , runner, , runnerArch] = values;
    const row = platformSupport
      .split("\n")
      .find((line) => line.includes(`(\`${target}\`)`));
    assert.ok(row, `missing platform documentation row for ${target}`);
    assert.ok(
      row.includes(`\`${runner}\` ${runnerArch}`),
      `platform documentation must bind ${target} to ${runner} ${runnerArch}`,
    );
  }

  assert.match(
    platformSupport,
    /verified 2026-09-03[\s\S]*immutable `v0\.7\.5` GitHub[\s\S]*d2969e73995cc139e6253e0c8a70f1d683f88e20/i,
  );
  assert.match(platformSupport, /workflow\s+`33709338577`[\s\S]*19 assets/i);
  assert.equal(
    platformSupport.match(/`v0\.7\.5` release-native acceptance passed/g)?.length,
    6,
    "every native row must name the exact v0.7.7 release receipt",
  );
  assert.match(platformSupport, /no exact npm `0\.7\.5` acceptance receipt is claimed/i);
  assert.match(
    platformSupport,
    /Attestation cannot begin\s+until all six jobs succeed/,
  );
  assert.match(platformSupport, /only a\s+retained successful run establishes that evidence/i);
  assert.match(
    platformSupport,
    /Upgrade,[\s\S]*still require\s+separately retained evidence/,
  );
  assert.doesNotMatch(platformSupport, /workflow packages but does not execute the exact resulting archive/i);
  assert.doesNotMatch(platformSupport, /no archive execution/i);
});
