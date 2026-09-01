#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  accessSync,
  constants,
  lstatSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

export const NATIVE_TARGETS = Object.freeze({
  "x86_64-apple-darwin": Object.freeze({
    artifact: "phantom-x86_64-apple-darwin",
    archive: "phantom-x86_64-apple-darwin.tar.gz",
    runner: "macos-15-intel",
    runnerOs: "macOS",
    runnerArch: "X64",
    platform: "darwin",
    arch: "x64",
    binaries: Object.freeze(["phantom", "phantom-mcp"]),
  }),
  "aarch64-apple-darwin": Object.freeze({
    artifact: "phantom-aarch64-apple-darwin",
    archive: "phantom-aarch64-apple-darwin.tar.gz",
    runner: "macos-15",
    runnerOs: "macOS",
    runnerArch: "ARM64",
    platform: "darwin",
    arch: "arm64",
    binaries: Object.freeze(["phantom", "phantom-mcp"]),
  }),
  "x86_64-unknown-linux-gnu": Object.freeze({
    artifact: "phantom-x86_64-unknown-linux-gnu",
    archive: "phantom-x86_64-unknown-linux-gnu.tar.gz",
    runner: "ubuntu-22.04",
    runnerOs: "Linux",
    runnerArch: "X64",
    platform: "linux",
    arch: "x64",
    binaries: Object.freeze(["phantom", "phantom-mcp"]),
  }),
  "aarch64-unknown-linux-gnu": Object.freeze({
    artifact: "phantom-aarch64-unknown-linux-gnu",
    archive: "phantom-aarch64-unknown-linux-gnu.tar.gz",
    runner: "ubuntu-22.04-arm",
    runnerOs: "Linux",
    runnerArch: "ARM64",
    platform: "linux",
    arch: "arm64",
    binaries: Object.freeze(["phantom", "phantom-mcp"]),
  }),
  "x86_64-pc-windows-msvc": Object.freeze({
    artifact: "phantom-x86_64-pc-windows-msvc",
    archive: "phantom-x86_64-pc-windows-msvc.zip",
    runner: "windows-latest",
    runnerOs: "Windows",
    runnerArch: "X64",
    platform: "win32",
    arch: "x64",
    binaries: Object.freeze(["phantom.exe", "phantom-mcp.exe"]),
  }),
  "aarch64-pc-windows-msvc": Object.freeze({
    artifact: "phantom-aarch64-pc-windows-msvc",
    archive: "phantom-aarch64-pc-windows-msvc.zip",
    runner: "windows-11-vs2026-arm",
    runnerOs: "Windows",
    runnerArch: "ARM64",
    platform: "win32",
    arch: "arm64",
    binaries: Object.freeze(["phantom.exe", "phantom-mcp.exe"]),
  }),
});

const MAX_ARCHIVE_BYTES = 100 * 1024 * 1024;
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

function fail(message) {
  throw new Error(message);
}

function run(command, args, label, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    encoding: "utf8",
    env: options.env ?? process.env,
    maxBuffer: 16 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
    timeout: options.timeout ?? 30_000,
    windowsHide: true,
  });
  if (result.error) fail(`${label} could not run: ${result.error.message}`);
  if (result.status !== 0 || result.signal !== null) {
    const stderr = result.stderr.trim();
    fail(
      `${label} failed with status=${result.status} signal=${result.signal}` +
        (stderr ? `: ${stderr}` : ""),
    );
  }
  return result.stdout;
}

function exactLines(output) {
  const normalized = output.replace(/\r\n/g, "\n").replace(/\n$/, "");
  return normalized === "" ? [] : normalized.split("\n");
}

function archiveDigest(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

export function validateNativeRuntime(target, env = process.env, runtime = process) {
  const contract = NATIVE_TARGETS[target];
  if (!contract) fail(`unsupported native release target: ${target}`);
  if (env.RUNNER_OS !== contract.runnerOs || env.RUNNER_ARCH !== contract.runnerArch) {
    fail(
      `native runner mismatch for ${target}: expected ${contract.runnerOs}/${contract.runnerArch}, ` +
        `got ${env.RUNNER_OS ?? "unset"}/${env.RUNNER_ARCH ?? "unset"}`,
    );
  }
  if (runtime.platform !== contract.platform || runtime.arch !== contract.arch) {
    fail(
      `native Node runtime mismatch for ${target}: expected ${contract.platform}/${contract.arch}, ` +
        `got ${runtime.platform}/${runtime.arch}`,
    );
  }
  return contract;
}

function validateTag(tag) {
  const match = tag.match(/^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/);
  if (!match) fail(`release tag must be stable v<semver>, got ${tag}`);
  return tag.slice(1);
}

function validateDownloadedArtifact(archivePath, contract) {
  const archive = resolve(archivePath);
  if (basename(archive) !== contract.archive) {
    fail(`archive name mismatch: expected ${contract.archive}, got ${basename(archive)}`);
  }
  const archiveStat = lstatSync(archive);
  if (!archiveStat.isFile() || archiveStat.isSymbolicLink()) {
    fail(`${contract.archive} must be one regular file`);
  }
  if (archiveStat.size < 1 || archiveStat.size > MAX_ARCHIVE_BYTES) {
    fail(`${contract.archive} must be between 1 byte and 100 MiB`);
  }

  const expectedFiles = [contract.archive, `${contract.archive}.spdx.json`].sort();
  const actualFiles = readdirSync(dirname(archive), { withFileTypes: true })
    .map((entry) => {
      if (!entry.isFile() || entry.isSymbolicLink()) {
        fail(`downloaded artifact contains a non-regular entry: ${entry.name}`);
      }
      return entry.name;
    })
    .sort();
  if (
    actualFiles.length !== expectedFiles.length ||
    actualFiles.some((name, index) => name !== expectedFiles[index])
  ) {
    fail(
      `downloaded artifact must contain exactly ${expectedFiles.join(", ")}; got ${actualFiles.join(", ")}`,
    );
  }
  return archive;
}

function inspectAndExtract(archive, contract, destination, runCommand) {
  const compressedTar = contract.archive.endsWith(".tar.gz");
  const listArgs = compressedTar ? ["-tzf", archive] : ["-tf", archive];
  const verboseArgs = compressedTar ? ["-tvzf", archive] : ["-tvf", archive];
  const extractArgs = compressedTar
    ? ["-xzf", archive, "-C", destination]
    : ["-xf", archive, "-C", destination];

  const members = exactLines(runCommand("tar", listArgs, `inspect ${contract.archive}`)).sort();
  const expectedMembers = [...contract.binaries].sort();
  if (
    members.length !== expectedMembers.length ||
    members.some((name, index) => name !== expectedMembers[index])
  ) {
    fail(
      `${contract.archive} must contain exactly ${expectedMembers.join(", ")}; got ${members.join(", ")}`,
    );
  }
  const verbose = exactLines(
    runCommand("tar", verboseArgs, `inspect types in ${contract.archive}`),
  );
  if (verbose.length !== expectedMembers.length || verbose.some((line) => !line.startsWith("-"))) {
    fail(`${contract.archive} members must each be one regular file`);
  }

  const before = archiveDigest(archive);
  runCommand("tar", extractArgs, `extract ${contract.archive}`);
  if (archiveDigest(archive) !== before) fail(`${contract.archive} changed during extraction`);

  const extractedNames = readdirSync(destination).sort();
  if (
    extractedNames.length !== expectedMembers.length ||
    extractedNames.some((name, index) => name !== expectedMembers[index])
  ) {
    fail(`extracted archive contains unexpected entries: ${extractedNames.join(", ")}`);
  }
  for (const name of expectedMembers) {
    const stat = lstatSync(join(destination, name));
    if (!stat.isFile() || stat.isSymbolicLink()) fail(`extracted ${name} is not a regular file`);
  }
}

function verifyVersion(binary, expected, runCommand) {
  accessSync(binary, constants.X_OK);
  const actual = runCommand(binary, ["--version"], `${basename(binary)} --version`)
    .replace(/\r\n/g, "\n")
    .replace(/\n$/, "");
  if (actual !== expected) fail(`${basename(binary)} --version must equal ${expected}; got ${actual}`);
}

export function runNativeReleaseSmoke({
  archivePath,
  target,
  tag,
  env = process.env,
  runtime = process,
  runCommand = run,
}) {
  if (
    typeof archivePath !== "string" ||
    archivePath === "" ||
    typeof target !== "string" ||
    target === "" ||
    typeof tag !== "string" ||
    tag === ""
  ) {
    fail("native release smoke requires a non-empty archive path, target, and release tag");
  }
  const contract = validateNativeRuntime(target, env, runtime);
  const version = validateTag(tag);
  const archive = validateDownloadedArtifact(archivePath, contract);
  const extractionDir = mkdtempSync(join(tmpdir(), "phantom-native-release-"));
  try {
    inspectAndExtract(archive, contract, extractionDir, runCommand);
    const phantom = join(extractionDir, contract.binaries[0]);
    const phantomMcp = join(extractionDir, contract.binaries[1]);
    verifyVersion(phantom, `phantom ${version}`, runCommand);
    verifyVersion(phantomMcp, `phantom-mcp ${version}`, runCommand);
    runCommand(
      process.execPath,
      [join(repoRoot, "scripts/release/mcp-stdio-smoke.mjs"), phantomMcp, "54"],
      "MCP stdio schema smoke",
      { cwd: repoRoot, timeout: 30_000 },
    );
    return { archive: contract.archive, target, version };
  } finally {
    rmSync(extractionDir, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  const args = process.argv.slice(2);
  if (args.length !== 0 && args.length !== 3) {
    fail(
      "usage: native-release-smoke.mjs [<archive> <target> <v-semver>] " +
        "or set PHANTOM_NATIVE_ARCHIVE, PHANTOM_NATIVE_TARGET, and PHANTOM_RELEASE_TAG",
    );
  }
  const result = runNativeReleaseSmoke({
    archivePath: args[0] ?? process.env.PHANTOM_NATIVE_ARCHIVE,
    target: args[1] ?? process.env.PHANTOM_NATIVE_TARGET,
    tag: args[2] ?? process.env.PHANTOM_RELEASE_TAG,
  });
  console.log(
    `native release smoke passed: ${result.archive} on ${result.target} at ${result.version}`,
  );
}
