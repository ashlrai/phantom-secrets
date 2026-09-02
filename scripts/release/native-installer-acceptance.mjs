#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  copyFileSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

import { validateNativeRuntime } from "./native-release-smoke.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

function fail(message) {
  throw new Error(message);
}

function run(command, args, label, env, expectFailure = false) {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
    env,
    maxBuffer: 16 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 120_000,
    windowsHide: true,
  });
  if (result.error) fail(`${label} could not run: ${result.error.message}`);
  const failed = result.status !== 0 || result.signal !== null;
  if (failed !== expectFailure) {
    const detail = (result.stderr || result.stdout).trim();
    fail(
      `${label} ${expectFailure ? "unexpectedly passed" : "failed"} with ` +
        `status=${result.status} signal=${result.signal}` +
        (detail ? `: ${detail}` : ""),
    );
  }
  return result;
}

function versionFromTag(tag) {
  if (!/^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(tag)) {
    fail(`installer acceptance requires a stable v<semver> tag, got ${tag}`);
  }
  return tag.slice(1);
}

function digest(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function snapshotTree(root, prefix = "") {
  const entries = [];
  for (const name of readdirSync(root).sort()) {
    const path = join(root, name);
    const relative = prefix ? `${prefix}/${name}` : name;
    const stat = lstatSync(path);
    if (stat.isSymbolicLink()) fail(`installer acceptance found unexpected symlink: ${relative}`);
    if (stat.isDirectory()) entries.push(...snapshotTree(path, relative));
    else if (stat.isFile()) entries.push(`${relative}:${digest(path)}`);
    else fail(`installer acceptance found unexpected filesystem entry: ${relative}`);
  }
  return entries;
}

export function acceptanceTempRoot(platform, env, fallback = tmpdir()) {
  // GitHub's Windows TEMP may use a rejected 8.3 alias; RUNNER_TEMP is the
  // per-job workspace whose path still exercises the production allowlist.
  if (
    platform === "win32" &&
    typeof env.RUNNER_TEMP === "string" &&
    env.RUNNER_TEMP.trim() !== ""
  ) {
    return env.RUNNER_TEMP;
  }
  return fallback;
}

function installerCommand(platform, env) {
  if (platform === "win32") {
    return {
      command: env.PHANTOM_TEST_PWSH || "pwsh.exe",
      args: [
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        join(repoRoot, "scripts/install.ps1"),
      ],
    };
  }
  return { command: "/bin/bash", args: [join(repoRoot, "scripts/install.sh")] };
}

export function runNativeInstallerAcceptance({
  archivePath,
  target,
  tag,
  env = process.env,
  runtime = process,
}) {
  if (!archivePath || !target || !tag) {
    fail("native installer acceptance requires an archive path, target, and release tag");
  }
  const contract = validateNativeRuntime(target, env, runtime);
  const version = versionFromTag(tag);
  const archive = resolve(archivePath);
  if (basename(archive) !== contract.archive) {
    fail(`archive name mismatch: expected ${contract.archive}, got ${basename(archive)}`);
  }
  const archiveStat = lstatSync(archive);
  if (!archiveStat.isFile() || archiveStat.isSymbolicLink()) {
    fail(`${contract.archive} must be one regular file`);
  }

  const root = mkdtempSync(
    join(acceptanceTempRoot(contract.platform, env), "phantom-native-installer-"),
  );
  const localRelease = join(root, "release");
  const home = join(root, "home");
  const installParent = join(root, "live");
  const install = join(installParent, "bin");
  mkdirSync(localRelease);
  mkdirSync(home);
  mkdirSync(installParent);
  const localArchive = join(localRelease, contract.archive);
  const sidecar = `${localArchive}.sha256`;
  copyFileSync(archive, localArchive);
  writeFileSync(sidecar, `${digest(localArchive)}  ${contract.archive}\n`, { mode: 0o600 });

  const installerEnv = {
    ...env,
    HOME: home,
    USERPROFILE: home,
    SHELL: "/bin/bash",
    PHANTOM_INSTALL_DIR: install,
    PHANTOM_TAG: tag,
    PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: "1",
    PHANTOM_TEST_LOCAL_RELEASE_DIR: localRelease,
    PHANTOM_TEST_DISABLE_PATH_PERSISTENCE: "1",
  };
  delete installerEnv.PHANTOM_REPO;
  delete installerEnv.PHANTOM_TEST_FAIL_AFTER_PROMOTION;
  const command = installerCommand(contract.platform, installerEnv);

  try {
    run(command.command, command.args, `native ${target} installer`, installerEnv);
    const receiptPath = join(install, ".phantom-install-source.json");
    const receipt = JSON.parse(readFileSync(receiptPath, "utf8"));
    const expectedReceipt = {
      schema_version: 1,
      source: "direct",
      version,
      target,
    };
    if (JSON.stringify(receipt) !== JSON.stringify(expectedReceipt)) {
      fail(`installer receipt mismatch: ${JSON.stringify(receipt)}`);
    }
    for (const [index, binaryName] of contract.binaries.entries()) {
      const product = index === 0 ? "phantom" : "phantom-mcp";
      const output = run(
        join(install, binaryName),
        ["--version"],
        `installed ${product} --version`,
        installerEnv,
      ).stdout.replace(/\r\n/g, "\n").replace(/\n$/, "");
      if (output !== `${product} ${version}`) {
        fail(`installed ${product} reported an unexpected version: ${output}`);
      }
    }

    const sentinelPath = join(install, ".phantom-accepted-test-sentinel");
    writeFileSync(sentinelPath, "accepted installation must survive rollback\n", {
      mode: 0o600,
    });
    const accepted = snapshotTree(install);
    const assertAcceptedInstallationPreserved = (label) => {
      const afterFailure = snapshotTree(install);
      if (JSON.stringify(afterFailure) !== JSON.stringify(accepted)) {
        fail(`${label} changed the accepted live installation`);
      }
      const residue = readdirSync(installParent).sort();
      if (residue.length !== 1 || residue[0] !== "bin") {
        fail(`${label} left transaction residue: ${residue.join(", ")}`);
      }
    };

    const rollbackFailure = run(
      command.command,
      command.args,
      `native ${target} installer controlled post-promotion failure`,
      { ...installerEnv, PHANTOM_TEST_FAIL_AFTER_PROMOTION: "1" },
      true,
    );
    if (!`${rollbackFailure.stdout}\n${rollbackFailure.stderr}`.includes(
      "test-only injected failure after promotion",
    )) {
      fail("controlled post-promotion failure did not reach the rollback seam");
    }
    assertAcceptedInstallationPreserved("controlled post-promotion rollback");

    writeFileSync(sidecar, `${"0".repeat(64)}  ${contract.archive}\n`, { mode: 0o600 });
    run(
      command.command,
      command.args,
      `native ${target} installer controlled checksum failure`,
      installerEnv,
      true,
    );
    assertAcceptedInstallationPreserved("controlled checksum failure");

    return { archive: contract.archive, target, version };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  const args = process.argv.slice(2);
  if (args.length !== 0 && args.length !== 3) {
    fail(
      "usage: native-installer-acceptance.mjs [<archive> <target> <v-semver>] " +
        "or set PHANTOM_NATIVE_ARCHIVE, PHANTOM_NATIVE_TARGET, and PHANTOM_RELEASE_TAG",
    );
  }
  const result = runNativeInstallerAcceptance({
    archivePath: args[0] ?? process.env.PHANTOM_NATIVE_ARCHIVE,
    target: args[1] ?? process.env.PHANTOM_NATIVE_TARGET,
    tag: args[2] ?? process.env.PHANTOM_RELEASE_TAG,
  });
  console.log(
    `native installer acceptance passed: ${result.archive} on ${result.target} at ${result.version}`,
  );
}
