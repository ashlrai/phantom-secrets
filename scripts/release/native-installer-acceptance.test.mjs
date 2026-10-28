import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

import {
  acceptanceTempRoot,
  runNativeInstallerAcceptance,
} from "./native-installer-acceptance.mjs";

const repoRoot = resolve(import.meta.dirname, "../..");
const normalCi = readFileSync(resolve(repoRoot, ".github/workflows/ci.yml"), "utf8");
const windowsInstallerStepName =
  "Exercise the Windows installer with the existing debug binaries";

// These workflow contracts use fixed YAML indentation. Stop at the next peer
// or ancestor so unrelated steps/jobs cannot satisfy or invalidate assertions.
function indentedBlock(source, header, indent) {
  const lines = source.split(/\r?\n/);
  const starts = lines.flatMap((line, index) =>
    line === `${" ".repeat(indent)}${header}` ? [index] : [],
  );
  assert.equal(starts.length, 1, `expected exactly one ${header} block`);
  const start = starts[0];
  const end = lines.findIndex(
    (line, index) => index > start && line.trim() && line.search(/\S/) <= indent,
  );
  return lines.slice(start, end < 0 ? lines.length : end).join("\n");
}

function assertWindowsInstallerAcceptance(source) {
  const job = indentedBlock(source, "test:", 2);
  const steps = indentedBlock(job, "steps:", 4);
  const step = indentedBlock(steps, `- name: ${windowsInstallerStepName}`, 6);

  assert.match(step, /if: runner\.os == 'Windows'/);
  assert.match(step, /Push-Location target\/debug/);
  assert.match(step, /Compress-Archive -LiteralPath phantom\.exe, phantom-mcp\.exe/);
  assert.match(step, /phantom-x86_64-pc-windows-msvc\.zip/);
  assert.match(step, /PHANTOM_NATIVE_TARGET = 'x86_64-pc-windows-msvc'/);
  assert.match(step, /PHANTOM_RELEASE_TAG = "v\$version"/);
  assert.match(step, /node scripts\/release\/native-installer-acceptance\.mjs/);
  assert.doesNotMatch(step, /cargo build|download-artifact|releases\/download/);
}

test("Windows acceptance uses the runner-owned temp directory", () => {
  assert.equal(
    acceptanceTempRoot(
      "win32",
      { RUNNER_TEMP: "D:\\a\\_temp" },
      "C:\\Users\\RUNNER~1\\AppData\\Local\\Temp",
    ),
    "D:\\a\\_temp",
  );
});

test("acceptance temp selection retains fail-closed platform fallbacks", () => {
  const fallback = "C:\\Users\\RUNNER~1\\AppData\\Local\\Temp";
  assert.equal(acceptanceTempRoot("win32", {}, fallback), fallback);
  assert.equal(acceptanceTempRoot("win32", { RUNNER_TEMP: "  " }, fallback), fallback);
  assert.equal(
    acceptanceTempRoot("linux", { RUNNER_TEMP: "/runner/temp" }, "/system/temp"),
    "/system/temp",
  );
});

test("native installer acceptance requires complete stable release identity", () => {
  assert.throws(
    () => runNativeInstallerAcceptance({}),
    /requires an archive path, target, and release tag/,
  );
  assert.throws(
    () =>
      runNativeInstallerAcceptance({
        archivePath: "unused",
        target: "x86_64-unknown-linux-gnu",
        tag: "v1.2.3-rc.1",
        env: { RUNNER_OS: "Linux", RUNNER_ARCH: "X64" },
        runtime: { platform: "linux", arch: "x64" },
      }),
    /stable v<semver>/,
  );
});

test("native installer acceptance fails before installation on runner mismatch", () => {
  assert.throws(
    () =>
      runNativeInstallerAcceptance({
        archivePath: "unused",
        target: "aarch64-pc-windows-msvc",
        tag: "v1.2.3",
        env: { RUNNER_OS: "Windows", RUNNER_ARCH: "X64" },
        runtime: { platform: "win32", arch: "x64" },
      }),
    /native runner mismatch/,
  );
});

test("installer local-release seams remain explicit test-only contracts", () => {
  for (const relative of [
    "scripts/install.sh",
    "scripts/install.ps1",
    "apps/web/public/install.sh",
    "apps/web/public/install.ps1",
  ]) {
    const source = readFileSync(resolve(repoRoot, relative), "utf8");
    assert.match(source, /PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES/);
    assert.match(source, /PHANTOM_TEST_LOCAL_RELEASE_DIR/);
    assert.match(source, /PHANTOM_TEST_FAIL_AFTER_PROMOTION/);
    assert.match(source, /test-only injected failure after promotion/);
  }
  const powerShell = readFileSync(resolve(repoRoot, "scripts/install.ps1"), "utf8");
  assert.match(powerShell, /PHANTOM_TEST_DISABLE_PATH_PERSISTENCE/);
  assert.match(powerShell, /persistent PATH mutation skipped/);

  const acceptance = readFileSync(
    resolve(repoRoot, "scripts/release/native-installer-acceptance.mjs"),
    "utf8",
  );
  assert.match(acceptance, /installerCommand\(contract\.platform, installerEnv\)/);
  assert.doesNotMatch(acceptance, /process\.env\.PHANTOM_TEST_PWSH/);
  assert.match(acceptance, /PHANTOM_TEST_FAIL_AFTER_PROMOTION: "1"/);
  assert.match(acceptance, /controlled post-promotion rollback/);
});

test("normal Windows CI exercises installer acceptance with existing debug binaries", () => {
  assertWindowsInstallerAcceptance(normalCi);
});

test("Windows installer contract accepts CRLF workflow line endings", () => {
  assertWindowsInstallerAcceptance(normalCi.replace(/\r?\n/g, "\r\n"));
});

const windowsInstallerStep = indentedBlock(
  indentedBlock(indentedBlock(normalCi, "test:", 2), "steps:", 4),
  `- name: ${windowsInstallerStepName}`,
  6,
);
const unrelatedStep = `      - name: Unrelated build
        run: cargo build
      - name: Unrelated download
        uses: actions/download-artifact@fixture # releases/download`;

test("Windows installer contract ignores preceding and following jobs", () => {
  assertWindowsInstallerAcceptance(`jobs:
  preceding:
    steps:
${unrelatedStep}
  test:
    steps:
${windowsInstallerStep}
  following:
    steps:
${unrelatedStep}
`);
});

test("Windows installer contract ignores preceding and following steps", () => {
  assertWindowsInstallerAcceptance(`jobs:
  test:
    steps:
${unrelatedStep}
${windowsInstallerStep}
${unrelatedStep}
`);
});

test("Windows installer contract rejects missing, misplaced, or duplicate steps", () => {
  for (const source of [
    `jobs:\n  other:\n    steps:\n${windowsInstallerStep}\n`,
    `jobs:\n  test:\n    steps:\n${unrelatedStep}\n`,
    `jobs:\n  test:\n    steps:\n${unrelatedStep}\n  other:\n    steps:\n${windowsInstallerStep}\n`,
    `jobs:\n  other:\n    steps:\n${windowsInstallerStep}\n  test:\n    steps:\n${unrelatedStep}\n`,
    `jobs:\n  test:\n    steps:\n${windowsInstallerStep}\n${windowsInstallerStep}\n`,
  ]) {
    assert.throws(() => assertWindowsInstallerAcceptance(source), /expected exactly one/);
  }
});

for (const forbidden of ["cargo build", "download-artifact", "releases/download"]) {
  test(`Windows installer contract rejects ${forbidden} inside its step`, () => {
    assert.throws(
      () => assertWindowsInstallerAcceptance(`jobs:
  test:
    steps:
${windowsInstallerStep}
          ${forbidden}
`),
      { code: "ERR_ASSERTION", operator: "doesNotMatch" },
    );
  });
}

test("Windows installer contract still requires every acceptance assertion", () => {
  for (const required of [
    "if: runner.os == 'Windows'",
    "Push-Location target/debug",
    "Compress-Archive -LiteralPath phantom.exe, phantom-mcp.exe",
    "phantom-x86_64-pc-windows-msvc.zip",
    "PHANTOM_NATIVE_TARGET = 'x86_64-pc-windows-msvc'",
    'PHANTOM_RELEASE_TAG = "v$version"',
    "node scripts/release/native-installer-acceptance.mjs",
  ]) {
    assert.throws(() => assertWindowsInstallerAcceptance(`jobs:
  test:
    steps:
${windowsInstallerStep.replace(required, "removed-required-contract")}
`), { code: "ERR_ASSERTION", operator: "match" });
  }
});
