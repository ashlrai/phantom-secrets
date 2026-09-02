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
  const start = normalCi.indexOf(
    "- name: Exercise the Windows installer with the existing debug binaries",
  );
  assert.ok(start >= 0, "normal CI must include native Windows installer acceptance");
  const end = normalCi.indexOf("\n\n  test-ignored:", start);
  assert.ok(end > start, "Windows installer acceptance must remain in the normal test job");
  const step = normalCi.slice(start, end);

  assert.match(step, /if: runner\.os == 'Windows'/);
  assert.match(step, /Push-Location target\/debug/);
  assert.match(step, /Compress-Archive -LiteralPath phantom\.exe, phantom-mcp\.exe/);
  assert.match(step, /phantom-x86_64-pc-windows-msvc\.zip/);
  assert.match(step, /PHANTOM_NATIVE_TARGET = 'x86_64-pc-windows-msvc'/);
  assert.match(step, /PHANTOM_RELEASE_TAG = "v\$version"/);
  assert.match(step, /node scripts\/release\/native-installer-acceptance\.mjs/);
  assert.doesNotMatch(step, /cargo build|download-artifact|releases\/download/);
});
