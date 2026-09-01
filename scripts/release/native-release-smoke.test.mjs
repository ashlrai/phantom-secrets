import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

import { NATIVE_TARGETS, validateNativeRuntime } from "./native-release-smoke.mjs";

const repoRoot = resolve(import.meta.dirname, "../..");
const workflow = readFileSync(resolve(repoRoot, ".github/workflows/release.yml"), "utf8");

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

function job(name, next) {
  const start = workflow.indexOf(`\n  ${name}:\n`);
  assert.notEqual(start, -1, `missing ${name} job`);
  const end = workflow.indexOf(`\n  ${next}:\n`, start + 1);
  assert.notEqual(end, -1, `missing ${next} job after ${name}`);
  return workflow.slice(start, end);
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

test("release workflow binds every exact artifact to one native runner", () => {
  const nativeJob = job("native-acceptance", "attest");
  assert.match(nativeJob, /\n    needs: build\n/);
  assert.match(nativeJob, /\n    runs-on: \$\{\{ matrix\.os \}\}\n/);
  assert.match(nativeJob, /actions\/download-artifact@[0-9a-f]{40}/);
  assert.match(nativeJob, /name: \$\{\{ matrix\.artifact \}\}/);
  assert.match(nativeJob, /native-release-smoke\.mjs/);
  assert.match(nativeJob, /PHANTOM_NATIVE_ARCHIVE: native-artifact\/\$\{\{ matrix\.archive \}\}/);
  assert.match(nativeJob, /PHANTOM_NATIVE_TARGET: \$\{\{ matrix\.target \}\}/);
  assert.match(nativeJob, /PHANTOM_RELEASE_TAG: \$\{\{ github\.ref_name \}\}/);

  const rows = matrixRows(nativeJob);
  assert.deepEqual([...rows.keys()].sort(), Object.keys(expected).sort());
  const buildRows = matrixRows(job("build", "native-acceptance"));
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

test("attestation cannot begin before every build and native acceptance succeeds", () => {
  const attestJob = job("attest", "release");
  assert.match(attestJob, /\n    needs: \[build, native-acceptance\]\n/);
  assert.doesNotMatch(attestJob, /continue-on-error:/);
  assert.doesNotMatch(job("native-acceptance", "attest"), /continue-on-error:/);
});
