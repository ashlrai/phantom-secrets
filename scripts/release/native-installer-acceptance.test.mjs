import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

import { runNativeInstallerAcceptance } from "./native-installer-acceptance.mjs";

const repoRoot = resolve(import.meta.dirname, "../..");

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
