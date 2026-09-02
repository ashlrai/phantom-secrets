#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";

const REGISTRY = "https://registry.npmjs.org/";
const REQUIRED_NODE = [22, 14, 0];
const REQUIRED_NPM = [11, 15, 0];
const TARGETS = Object.freeze({
  "x86_64-apple-darwin": Object.freeze({
    platform: "darwin", arch: "x64", runnerOs: "macOS", runnerArch: "X64",
  }),
  "aarch64-apple-darwin": Object.freeze({
    platform: "darwin", arch: "arm64", runnerOs: "macOS", runnerArch: "ARM64",
  }),
  "x86_64-unknown-linux-gnu": Object.freeze({
    platform: "linux", arch: "x64", runnerOs: "Linux", runnerArch: "X64",
  }),
  "aarch64-unknown-linux-gnu": Object.freeze({
    platform: "linux", arch: "arm64", runnerOs: "Linux", runnerArch: "ARM64",
  }),
  "x86_64-pc-windows-msvc": Object.freeze({
    platform: "win32", arch: "x64", runnerOs: "Windows", runnerArch: "X64",
  }),
  "aarch64-pc-windows-msvc": Object.freeze({
    platform: "win32", arch: "arm64", runnerOs: "Windows", runnerArch: "ARM64",
  }),
});

function fail(message) {
  throw new Error(message);
}

function parseVersion(value, label) {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/.exec(value.trim());
  if (!match) fail(`${label} returned an invalid semantic version: ${value.trim()}`);
  return match.slice(1).map(Number);
}

function atLeast(actual, required) {
  for (let index = 0; index < required.length; index += 1) {
    if (actual[index] > required[index]) return true;
    if (actual[index] < required[index]) return false;
  }
  return true;
}

function run(command, args, label, env = process.env) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    env,
    maxBuffer: 16 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 180_000,
    windowsHide: true,
  });

  if (result.error) fail(`${label} could not run: ${result.error.message}`);
  process.stdout.write(result.stdout);
  process.stderr.write(result.stderr);
  if (result.status !== 0 || result.signal !== null) {
    fail(`${label} failed with status=${result.status} signal=${result.signal}`);
  }
  return result.stdout;
}

function requireExactVersionLine(output, expected, label) {
  const lines = output
    .replace(/\r\n/g, "\n")
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  if (lines.length !== 1 || lines[0] !== expected) {
    fail(`${label} output must be exactly ${JSON.stringify(expected)}; got ${JSON.stringify(lines)}`);
  }
}

function requireRunnerIdentity() {
  const expectedTarget = process.env.PHANTOM_EXPECTED_TARGET;
  const expectedPlatform = process.env.PHANTOM_EXPECTED_PLATFORM;
  const expectedArch = process.env.PHANTOM_EXPECTED_ARCH;
  const expectedRunnerOs = process.env.PHANTOM_EXPECTED_RUNNER_OS;
  const expectedRunnerArch = process.env.PHANTOM_EXPECTED_RUNNER_ARCH;
  const contract = TARGETS[expectedTarget];
  if (!expectedTarget || !expectedPlatform || !expectedArch || !expectedRunnerOs || !expectedRunnerArch) {
    fail("the target and all expected platform and runner identity variables are required");
  }
  if (
    !contract ||
    contract.platform !== expectedPlatform ||
    contract.arch !== expectedArch ||
    contract.runnerOs !== expectedRunnerOs ||
    contract.runnerArch !== expectedRunnerArch
  ) {
    fail(`the configured runner identity does not match the closed contract for ${expectedTarget}`);
  }
  if (process.platform !== expectedPlatform || process.arch !== expectedArch) {
    fail(`expected Node host ${expectedPlatform}/${expectedArch}; got ${process.platform}/${process.arch}`);
  }
  if (process.env.RUNNER_OS !== expectedRunnerOs || process.env.RUNNER_ARCH !== expectedRunnerArch) {
    fail(
      `expected GitHub runner ${expectedRunnerOs}/${expectedRunnerArch}; ` +
        `got ${process.env.RUNNER_OS ?? "unset"}/${process.env.RUNNER_ARCH ?? "unset"}`,
    );
  }
}

function requirePackageMetadata(npmCli, env, name, version, approvedIntegrity) {
  const output = run(
    process.execPath,
    [
      npmCli,
      "view",
      `${name}@${version}`,
      "name",
      "version",
      "dist.integrity",
      "dist.tarball",
      "--json",
      `--registry=${REGISTRY}`,
    ],
    `${name} public metadata`,
    env,
  );
  const metadata = JSON.parse(output);
  const tarball = new URL(metadata["dist.tarball"]);
  if (
    metadata.name !== name ||
    metadata.version !== version ||
    metadata["dist.integrity"] !== approvedIntegrity ||
    tarball.protocol !== "https:" ||
    tarball.hostname !== "registry.npmjs.org" ||
    tarball.pathname !== `/${name}/-/${name}-${version}.tgz`
  ) {
    fail(`${name}@${version} public metadata or integrity does not match the approved candidate`);
  }
  return metadata;
}

function requireCandidateTags(npmCli, env, name, version, previousLatest) {
  const output = run(
    process.execPath,
    [npmCli, "view", name, "dist-tags", "--json", `--registry=${REGISTRY}`],
    `${name} dist-tags`,
    env,
  );
  const tags = JSON.parse(output);
  if (tags.latest !== previousLatest || tags["release-candidate"] !== version) {
    fail(`${name} dist-tags drifted before candidate acceptance`);
  }
  return tags;
}

const version = process.env.PHANTOM_NPM_ACCEPTANCE_VERSION;
if (!/^\d+\.\d+\.\d+$/.test(version ?? "")) {
  fail("PHANTOM_NPM_ACCEPTANCE_VERSION must be an exact stable semantic version");
}

requireRunnerIdentity();
const expectedSourceSha = process.env.PHANTOM_RELEASE_SOURCE_SHA;
const releaseTag = process.env.PHANTOM_RELEASE_TAG;
if (!/^[0-9a-f]{40}$/.test(expectedSourceSha ?? "") || releaseTag !== `v${version}`) {
  fail("the exact release source SHA and matching release tag are required");
}
const observedHead = run("git", ["rev-parse", "HEAD"], "validation commit").trim();
if (observedHead !== process.env.GITHUB_SHA) {
  fail(`checked-out validation commit ${observedHead} does not match GITHUB_SHA`);
}
const observedSourceSha = run("git", ["rev-parse", "HEAD^"], "released source parent").trim();
if (observedSourceSha !== expectedSourceSha) {
  fail(`validation commit parent ${observedSourceSha} does not match released source ${expectedSourceSha}`);
}
if (run("git", ["status", "--porcelain=v1"], "clean checkout") !== "") {
  fail("candidate acceptance requires a clean validation checkout");
}
const nodeVersion = parseVersion(process.versions.node, "node");
if (!atLeast(nodeVersion, REQUIRED_NODE)) {
  fail(`Node >=${REQUIRED_NODE.join(".")} is required; got ${process.versions.node}`);
}

const npmCli = process.env.PHANTOM_NPM_CLI;
if (!npmCli || !isAbsolute(npmCli) || !existsSync(npmCli)) {
  fail("PHANTOM_NPM_CLI must name an existing absolute npm-cli.js path");
}
const npmOutput = run(process.execPath, [npmCli, "--version"], "npm version");
const npmVersion = parseVersion(npmOutput, "npm");
if (!atLeast(npmVersion, REQUIRED_NPM) || npmOutput.trim() !== REQUIRED_NPM.join(".")) {
  fail(`npm exactly ${REQUIRED_NPM.join(".")} is required; got ${npmOutput.trim()}`);
}

const configuredHome = process.platform === "win32"
  ? process.env.USERPROFILE || process.env.HOME || homedir()
  : process.env.HOME || homedir();
if (!configuredHome || !isAbsolute(configuredHome)) {
  fail("a private absolute runner home is required");
}
const binaryCache = resolve(configuredHome, ".phantom-secrets");
if (existsSync(binaryCache)) {
  fail(`fresh-host acceptance requires an absent Phantom cache: ${binaryCache}`);
}

const primaryIntegrity = process.env.PHANTOM_APPROVED_PRIMARY_INTEGRITY;
const mcpIntegrity = process.env.PHANTOM_APPROVED_MCP_INTEGRITY;
const previousLatest = process.env.PHANTOM_PREVIOUS_NPM_LATEST;
if (!primaryIntegrity || !mcpIntegrity || !/^\d+\.\d+\.\d+$/.test(previousLatest ?? "")) {
  fail("approved package integrities and the previous latest version are required");
}

const npmCache = mkdtempSync(join(tmpdir(), "phantom-npm-acceptance-"));
const isolatedEnv = { ...process.env, npm_config_cache: npmCache };
let mcpOutput;
let cliOutput;
let primaryMetadata;
let mcpMetadata;
let primaryTags;
let mcpTags;
let cacheReceipts;
try {
  primaryMetadata = requirePackageMetadata(npmCli, isolatedEnv, "phantom-secrets", version, primaryIntegrity);
  mcpMetadata = requirePackageMetadata(npmCli, isolatedEnv, "phantom-secrets-mcp", version, mcpIntegrity);
  primaryTags = requireCandidateTags(npmCli, isolatedEnv, "phantom-secrets", version, previousLatest);
  mcpTags = requireCandidateTags(npmCli, isolatedEnv, "phantom-secrets-mcp", version, previousLatest);

  mcpOutput = run(
    process.execPath,
    [
      npmCli,
      "exec",
      "--yes",
      `--package=phantom-secrets-mcp@${version}`,
      `--registry=${REGISTRY}`,
      "--",
      "phantom-mcp",
      "--version",
    ],
    "exact MCP candidate",
    isolatedEnv,
  );
  requireExactVersionLine(mcpOutput, `phantom-mcp ${version}`, "MCP candidate");

  cliOutput = run(
    process.execPath,
    [
      npmCli,
      "exec",
      "--yes",
      `--package=phantom-secrets@${version}`,
      `--registry=${REGISTRY}`,
      "--",
      "phantom",
      "--version",
    ],
    "exact CLI candidate",
    isolatedEnv,
  );
  requireExactVersionLine(cliOutput, `phantom ${version}`, "CLI candidate");

  primaryTags = requireCandidateTags(npmCli, isolatedEnv, "phantom-secrets", version, previousLatest);
  mcpTags = requireCandidateTags(npmCli, isolatedEnv, "phantom-secrets-mcp", version, previousLatest);

  const binDir = join(binaryCache, "bin");
  const executableSuffix = process.platform === "win32" ? ".exe" : "";
  cacheReceipts = ["phantom-mcp", "phantom"].map((binary) => {
    const binaryPath = join(binDir, `${binary}${executableSuffix}`);
    const manifestPath = `${binaryPath}.manifest.json`;
    const markerPath = join(binDir, `.phantom-install-source.${binary === "phantom" ? "npm-cli" : "npm-mcp"}`);
    if (!existsSync(binaryPath) || !existsSync(manifestPath) || readFileSync(markerPath, "utf8") !== "npm\n") {
      fail(`${binary} did not leave the expected npm cache receipt`);
    }
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    if (manifest.version !== version || !/^[0-9a-f]{64}$/.test(manifest.sha256 ?? "")) {
      fail(`${binary} cache manifest is not bound to ${version}`);
    }
    const observedSha256 = createHash("sha256").update(readFileSync(binaryPath)).digest("hex");
    if (observedSha256 !== manifest.sha256) {
      fail(`${binary} cache binary does not match its verified manifest`);
    }
    return { binary, manifest };
  });
} finally {
  rmSync(npmCache, { force: true, recursive: true });
}

const receiptPath = process.env.PHANTOM_NPM_ACCEPTANCE_RECEIPT;
if (!receiptPath || !isAbsolute(receiptPath)) {
  fail("PHANTOM_NPM_ACCEPTANCE_RECEIPT must be an absolute path");
}
writeFileSync(
  receiptPath,
  `${JSON.stringify(
    {
      schema_version: 1,
      accepted: true,
      repository: process.env.GITHUB_REPOSITORY,
      workflow_ref: process.env.GITHUB_WORKFLOW_REF,
      validation_commit: observedHead,
      release_tag: releaseTag,
      release_sha: observedSourceSha,
      version,
      run_id: process.env.GITHUB_RUN_ID,
      run_attempt: process.env.GITHUB_RUN_ATTEMPT,
      run_url: `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}`,
      runner_os: process.env.RUNNER_OS,
      runner_arch: process.env.RUNNER_ARCH,
      node_platform: process.platform,
      node_arch: process.arch,
      runner_name: process.env.RUNNER_NAME,
      runner_image_os: process.env.ImageOS ?? null,
      runner_image_version: process.env.ImageVersion ?? null,
      node_version: process.versions.node,
      npm_version: npmOutput.trim(),
      registry: REGISTRY,
      previous_latest_expected: previousLatest,
      candidate_tag_name: "release-candidate",
      target: process.env.PHANTOM_EXPECTED_TARGET,
      primary_metadata: primaryMetadata,
      mcp_metadata: mcpMetadata,
      primary_dist_tags: primaryTags,
      mcp_dist_tags: mcpTags,
      mcp_output: mcpOutput.trim(),
      primary_output: cliOutput.trim(),
      cache_receipts: cacheReceipts,
    },
    null,
    2,
  )}\n`,
  { mode: 0o600 },
);

console.log(
  `npm candidate acceptance passed for ${version} on ` +
    `${process.env.RUNNER_OS}/${process.env.RUNNER_ARCH} (${process.platform}/${process.arch})`,
);
