#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const REGISTRY = "https://registry.npmjs.org/";
const REPOSITORY = "ashlrai/phantom-secrets";
const REQUIRED_NODE = [22, 14, 0];
const REQUIRED_NPM = "11.15.0";
const EXACT_PACK_FILES = Object.freeze([
  "LICENSE",
  "README.md",
  "bin/cli.js",
  "install.js",
  "package.json",
]);
const MODES = new Set(["prepublication", "published-candidate"]);
const SAFE_HOST_ENV_KEYS = Object.freeze([
  "PATH",
  "Path",
  "PATHEXT",
  "SYSTEMROOT",
  "SystemRoot",
  "WINDIR",
  "COMSPEC",
  "ComSpec",
  "TEMP",
  "TMP",
  "TMPDIR",
  "LANG",
  "LC_ALL",
  "TERM",
  "CI",
]);

export const NPM_ACCEPTANCE_TARGETS = Object.freeze({
  "x86_64-apple-darwin": Object.freeze({
    platform: "darwin",
    arch: "x64",
    runnerOs: "macOS",
    runnerArch: "X64",
    archive: "phantom-x86_64-apple-darwin.tar.gz",
  }),
  "aarch64-apple-darwin": Object.freeze({
    platform: "darwin",
    arch: "arm64",
    runnerOs: "macOS",
    runnerArch: "ARM64",
    archive: "phantom-aarch64-apple-darwin.tar.gz",
  }),
  "x86_64-unknown-linux-gnu": Object.freeze({
    platform: "linux",
    arch: "x64",
    runnerOs: "Linux",
    runnerArch: "X64",
    archive: "phantom-x86_64-unknown-linux-gnu.tar.gz",
  }),
  "aarch64-unknown-linux-gnu": Object.freeze({
    platform: "linux",
    arch: "arm64",
    runnerOs: "Linux",
    runnerArch: "ARM64",
    archive: "phantom-aarch64-unknown-linux-gnu.tar.gz",
  }),
  "x86_64-pc-windows-msvc": Object.freeze({
    platform: "win32",
    arch: "x64",
    runnerOs: "Windows",
    runnerArch: "X64",
    archive: "phantom-x86_64-pc-windows-msvc.zip",
  }),
  "aarch64-pc-windows-msvc": Object.freeze({
    platform: "win32",
    arch: "arm64",
    runnerOs: "Windows",
    runnerArch: "ARM64",
    archive: "phantom-aarch64-pc-windows-msvc.zip",
  }),
});

function fail(message) {
  throw new Error(message);
}

function parseVersion(value, label) {
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(value?.trim() ?? "");
  if (!match) fail(`${label} must be an exact stable semantic version`);
  return match.slice(1).map(Number);
}

function atLeast(actual, required) {
  for (let index = 0; index < required.length; index += 1) {
    if (actual[index] > required[index]) return true;
    if (actual[index] < required[index]) return false;
  }
  return true;
}

function isSha512Integrity(value) {
  if (!/^sha512-[A-Za-z0-9+/]+={0,2}$/.test(value ?? "")) return false;
  const encoded = value.slice("sha512-".length);
  const digest = Buffer.from(encoded, "base64");
  return digest.length === 64 && digest.toString("base64") === encoded;
}

export function validateAcceptanceConfig(env) {
  const mode = env.PHANTOM_NPM_ACCEPTANCE_MODE;
  if (!MODES.has(mode)) {
    fail("PHANTOM_NPM_ACCEPTANCE_MODE must be prepublication or published-candidate");
  }

  const version = env.PHANTOM_NPM_ACCEPTANCE_VERSION;
  parseVersion(version, "PHANTOM_NPM_ACCEPTANCE_VERSION");
  const previousLatest = env.PHANTOM_PREVIOUS_NPM_LATEST;
  parseVersion(previousLatest, "PHANTOM_PREVIOUS_NPM_LATEST");
  const previousCandidate = env.PHANTOM_PREVIOUS_NPM_CANDIDATE;
  parseVersion(previousCandidate, "PHANTOM_PREVIOUS_NPM_CANDIDATE");
  if (previousLatest === version) {
    fail("the approved previous latest version must differ from the candidate version");
  }
  if (previousCandidate === version) {
    fail("the approved previous candidate version must differ from the candidate version");
  }

  const releaseTag = env.PHANTOM_RELEASE_TAG;
  const releaseSha = env.PHANTOM_RELEASE_SOURCE_SHA;
  if (releaseTag !== `v${version}` || !/^[0-9a-f]{40}$/.test(releaseSha ?? "")) {
    fail("the matching release tag and exact lowercase 40-character source SHA are required");
  }

  const primaryIntegrity = env.PHANTOM_APPROVED_PRIMARY_INTEGRITY ?? "";
  const mcpIntegrity = env.PHANTOM_APPROVED_MCP_INTEGRITY ?? "";
  if (mode === "published-candidate") {
    if (!isSha512Integrity(primaryIntegrity) || !isSha512Integrity(mcpIntegrity)) {
      fail("published-candidate mode requires both approved sha512 integrity values");
    }
  } else if (primaryIntegrity !== "" || mcpIntegrity !== "") {
    fail("prepublication mode rejects public integrity inputs because no npm version may exist yet");
  }

  return {
    mode,
    version,
    previousLatest,
    previousCandidate,
    releaseTag,
    releaseSha,
    primaryIntegrity: primaryIntegrity || null,
    mcpIntegrity: mcpIntegrity || null,
  };
}

export function validateWorkflowIdentity(env, config) {
  const expectedRef = `refs/tags/${config.releaseTag}`;
  const expectedWorkflowRef =
    `${REPOSITORY}/.github/workflows/npm-candidate-acceptance.yml@${expectedRef}`;
  if (env.GITHUB_REPOSITORY !== REPOSITORY) {
    fail(`candidate acceptance is restricted to ${REPOSITORY}`);
  }
  if (env.GITHUB_REF !== expectedRef) {
    fail(`workflow dispatch must use --ref ${config.releaseTag}; got ${env.GITHUB_REF ?? "unset"}`);
  }
  if (env.GITHUB_SHA !== config.releaseSha || env.GITHUB_WORKFLOW_SHA !== config.releaseSha) {
    fail("the triggering ref SHA and workflow definition SHA must both equal the release source SHA");
  }
  if (env.GITHUB_WORKFLOW_REF !== expectedWorkflowRef) {
    fail(`workflow definition must be loaded from ${expectedWorkflowRef}`);
  }
  return {
    githubRef: env.GITHUB_REF,
    githubSha: env.GITHUB_SHA,
    workflowRef: env.GITHUB_WORKFLOW_REF,
    workflowSha: env.GITHUB_WORKFLOW_SHA,
  };
}

export function buildCandidateChildEnv(env, acceptanceHome, npmCache, npmConfigFiles) {
  const childEnv = {};
  for (const key of SAFE_HOST_ENV_KEYS) {
    if (Object.hasOwn(env, key) && typeof env[key] === "string") {
      childEnv[key] = env[key];
    }
  }
  childEnv.HOME = acceptanceHome;
  childEnv.USERPROFILE = acceptanceHome;
  childEnv.npm_config_cache = npmCache;
  childEnv.npm_config_registry = REGISTRY;
  childEnv.npm_config_userconfig = npmConfigFiles.user;
  childEnv.npm_config_globalconfig = npmConfigFiles.global;
  childEnv.npm_config_audit = "false";
  childEnv.npm_config_fund = "false";
  childEnv.npm_config_update_notifier = "false";
  return childEnv;
}

export function validateCandidateTagState(
  tags,
  mode,
  version,
  previousLatest,
  previousCandidate,
  name,
) {
  if (!tags || typeof tags !== "object" || Array.isArray(tags)) {
    fail(`${name} dist-tags response must be an object`);
  }
  if (tags.latest !== previousLatest) {
    fail(`${name} latest must remain ${previousLatest}; got ${tags.latest ?? "unset"}`);
  }
  if (mode === "published-candidate" && tags["release-candidate"] !== version) {
    fail(`${name} release-candidate must be exactly ${version}`);
  }
  if (mode === "prepublication" && tags["release-candidate"] !== previousCandidate) {
    fail(
      `${name} release-candidate must remain ${previousCandidate} before publication; ` +
        `got ${tags["release-candidate"] ?? "unset"}`,
    );
  }
  return tags;
}

export function validatePackReceipt(packs, name, version) {
  if (!Array.isArray(packs) || packs.length !== 1) {
    fail(`${name} must produce exactly one npm pack receipt`);
  }
  const pack = packs[0];
  const files = Array.isArray(pack.files)
    ? pack.files.map(({ path }) => path).sort()
    : [];
  if (
    pack.name !== name ||
    pack.version !== version ||
    pack.filename !== `${name}-${version}.tgz` ||
    pack.entryCount !== EXACT_PACK_FILES.length ||
    JSON.stringify(files) !== JSON.stringify(EXACT_PACK_FILES) ||
    !isSha512Integrity(pack.integrity) ||
    !/^[0-9a-f]{40}$/.test(pack.shasum ?? "")
  ) {
    fail(`${name}@${version} pack receipt does not match the closed package contract`);
  }
  return pack;
}

function runResult(command, args, label, env, { cwd, print = true } = {}) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    env,
    maxBuffer: 16 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 180_000,
    windowsHide: true,
  });

  if (result.error) fail(`${label} could not run: ${result.error.message}`);
  if (print) {
    process.stdout.write(result.stdout);
    process.stderr.write(result.stderr);
  }
  return result;
}

function run(command, args, label, env, options) {
  if (!env || typeof env !== "object") {
    fail(`${label} requires an explicit scrubbed child environment`);
  }
  const result = runResult(command, args, label, env, options);
  if (result.status !== 0 || result.signal !== null) {
    fail(`${label} failed with status=${result.status} signal=${result.signal}`);
  }
  return result.stdout;
}

function parseJson(output, label) {
  try {
    return JSON.parse(output);
  } catch (error) {
    fail(`${label} returned invalid JSON: ${error.message}`);
  }
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

function requireRunnerIdentity(env) {
  const expectedTarget = env.PHANTOM_EXPECTED_TARGET;
  const expectedPlatform = env.PHANTOM_EXPECTED_PLATFORM;
  const expectedArch = env.PHANTOM_EXPECTED_ARCH;
  const expectedRunnerOs = env.PHANTOM_EXPECTED_RUNNER_OS;
  const expectedRunnerArch = env.PHANTOM_EXPECTED_RUNNER_ARCH;
  const contract = NPM_ACCEPTANCE_TARGETS[expectedTarget];
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
  if (env.RUNNER_OS !== expectedRunnerOs || env.RUNNER_ARCH !== expectedRunnerArch) {
    fail(
      `expected GitHub runner ${expectedRunnerOs}/${expectedRunnerArch}; ` +
        `got ${env.RUNNER_OS ?? "unset"}/${env.RUNNER_ARCH ?? "unset"}`,
    );
  }
  return contract;
}

function requireCleanTaggedSource(config, childEnv) {
  const observedHead = run(
    "git",
    ["rev-parse", "HEAD"],
    "release source checkout",
    childEnv,
  ).trim();
  const observedTagType = run(
    "git",
    ["cat-file", "-t", `refs/tags/${config.releaseTag}`],
    "annotated release tag",
    childEnv,
  ).trim();
  const observedTagSha = run(
    "git",
    ["rev-parse", `refs/tags/${config.releaseTag}^{commit}`],
    "release tag source",
    childEnv,
  ).trim();
  if (observedTagType !== "tag") {
    fail(`${config.releaseTag} must be an annotated tag`);
  }
  if (observedHead !== config.releaseSha || observedTagSha !== config.releaseSha) {
    fail(
      `checked-out source ${observedHead} and ${config.releaseTag} source ${observedTagSha} ` +
        `must both equal ${config.releaseSha}`,
    );
  }
  if (run("git", ["status", "--porcelain=v1"], "clean release source", childEnv) !== "") {
    fail("npm acceptance requires a clean exact-tag checkout");
  }
  return observedHead;
}

function requireImmutableGitHubRelease(config, targetContract, env) {
  const output = run(
    "gh",
    [
      "api",
      "--method",
      "GET",
      "--header",
      "X-GitHub-Api-Version: 2022-11-28",
      `repos/${REPOSITORY}/releases/tags/${config.releaseTag}`,
    ],
    "immutable GitHub Release",
    env,
    { print: false },
  );
  const release = parseJson(output, "GitHub Release API");
  const assetNames = new Set((release.assets ?? []).map(({ name }) => name));
  const requiredAssets = [targetContract.archive, `${targetContract.archive}.sha256`];
  if (
    release.tag_name !== config.releaseTag ||
    release.draft !== false ||
    release.prerelease !== false ||
    release.immutable !== true ||
    requiredAssets.some((name) => !assetNames.has(name))
  ) {
    fail(`GitHub Release ${config.releaseTag} is missing, mutable, non-final, or lacks target assets`);
  }
  return {
    id: release.id,
    url: release.html_url,
    tag: release.tag_name,
    immutable: release.immutable,
    target_assets: requiredAssets,
  };
}

function npmJson(npmCli, args, label, env) {
  return parseJson(
    run(process.execPath, [npmCli, ...args, `--registry=${REGISTRY}`], label, env),
    label,
  );
}

function requirePackageMetadata(npmCli, env, name, version, approvedIntegrity) {
  const metadata = npmJson(
    npmCli,
    ["view", `${name}@${version}`, "name", "version", "dist.integrity", "dist.tarball", "--json"],
    `${name} public metadata`,
    env,
  );
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

function requireCandidateTags(npmCli, env, name, config) {
  const tags = npmJson(
    npmCli,
    ["view", name, "dist-tags", "--json"],
    `${name} dist-tags`,
    env,
  );
  return validateCandidateTagState(
    tags,
    config.mode,
    config.version,
    config.previousLatest,
    config.previousCandidate,
    name,
  );
}

function requireVersionAbsent(npmCli, env, name, version) {
  const values = npmJson(
    npmCli,
    ["view", name, "versions", "--json"],
    `${name} public versions`,
    env,
  );
  const versions = Array.isArray(values) ? values : [values];
  if (versions.includes(version)) {
    fail(`${name}@${version} is already public; prepublication acceptance requires an unburned version`);
  }
}

function packLocalPackage(npmCli, env, packageDirectory, packDirectory, name, version) {
  const output = run(
    process.execPath,
    [npmCli, "pack", "--json", "--pack-destination", packDirectory],
    `pack ${name} from tagged source`,
    env,
    { cwd: packageDirectory },
  );
  const pack = validatePackReceipt(parseJson(output, `${name} npm pack`), name, version);
  const tarballPath = resolve(packDirectory, pack.filename);
  if (!existsSync(tarballPath) || !lstatSync(tarballPath).isFile()) {
    fail(`${name} did not produce the expected regular tarball`);
  }
  const sha256 = createHash("sha256").update(readFileSync(tarballPath)).digest("hex");
  return {
    spec: pathToFileURL(tarballPath).href,
    receipt: {
      name: pack.name,
      version: pack.version,
      filename: pack.filename,
      integrity: pack.integrity,
      shasum: pack.shasum,
      sha256,
      entry_count: pack.entryCount,
      files: pack.files.map(({ path }) => path).sort(),
    },
  };
}

function requireCacheReceipts(binaryCache, version) {
  const binDir = join(binaryCache, "bin");
  const executableSuffix = process.platform === "win32" ? ".exe" : "";
  return ["phantom-mcp", "phantom"].map((binary) => {
    const binaryPath = join(binDir, `${binary}${executableSuffix}`);
    const manifestPath = `${binaryPath}.manifest.json`;
    const markerPath = join(binDir, `.phantom-install-source.${binary === "phantom" ? "npm-cli" : "npm-mcp"}`);
    if (
      !existsSync(binaryPath) ||
      !existsSync(manifestPath) ||
      !existsSync(markerPath) ||
      readFileSync(markerPath, "utf8") !== "npm\n"
    ) {
      fail(`${binary} did not leave the expected npm cache receipt`);
    }
    const manifest = parseJson(readFileSync(manifestPath, "utf8"), `${binary} cache manifest`);
    if (
      Object.keys(manifest).sort().join(",") !== "sha256,version" ||
      manifest.version !== version ||
      !/^[0-9a-f]{64}$/.test(manifest.sha256 ?? "")
    ) {
      fail(`${binary} cache manifest is not exactly bound to ${version}`);
    }
    const observedSha256 = createHash("sha256").update(readFileSync(binaryPath)).digest("hex");
    if (observedSha256 !== manifest.sha256) {
      fail(`${binary} cache binary does not match its verified manifest`);
    }
    return { binary, manifest };
  });
}

export function runNpmCandidateAcceptance(env = process.env) {
  const config = validateAcceptanceConfig(env);
  const targetContract = requireRunnerIdentity(env);
  const workflowIdentity = validateWorkflowIdentity(env, config);

  const nodeVersion = parseVersion(process.versions.node, "node runtime version");
  if (!atLeast(nodeVersion, REQUIRED_NODE)) {
    fail(`Node >=${REQUIRED_NODE.join(".")} is required; got ${process.versions.node}`);
  }

  const npmCli = env.PHANTOM_NPM_CLI;
  if (!npmCli || !isAbsolute(npmCli) || !existsSync(npmCli)) {
    fail("PHANTOM_NPM_CLI must name an existing absolute npm-cli.js path");
  }
  const acceptanceHome = env.PHANTOM_ACCEPTANCE_HOME;
  if (!acceptanceHome || !isAbsolute(acceptanceHome)) {
    fail("PHANTOM_ACCEPTANCE_HOME must be a private absolute runner path");
  }
  const binaryCache = resolve(acceptanceHome, ".phantom-secrets");
  if (existsSync(acceptanceHome) || existsSync(binaryCache)) {
    fail(`fresh-host acceptance requires an absent private home: ${acceptanceHome}`);
  }
  mkdirSync(acceptanceHome, { recursive: false, mode: 0o700 });

  const registryCache = mkdtempSync(join(tmpdir(), "phantom-npm-registry-"));
  const executionCache = mkdtempSync(join(tmpdir(), "phantom-npm-execution-"));
  const packCache = mkdtempSync(join(tmpdir(), "phantom-npm-pack-cache-"));
  const packDirectory = mkdtempSync(join(tmpdir(), "phantom-npm-packs-"));
  const userNpmConfig = join(acceptanceHome, "empty-user.npmrc");
  const globalNpmConfig = join(acceptanceHome, "empty-global.npmrc");
  writeFileSync(userNpmConfig, "# Intentionally empty for npm acceptance.\n", {
    flag: "wx",
    mode: 0o600,
  });
  writeFileSync(globalNpmConfig, "# Intentionally empty for npm acceptance.\n", {
    flag: "wx",
    mode: 0o600,
  });
  const npmConfigFiles = { user: userNpmConfig, global: globalNpmConfig };
  const sourceEnv = buildCandidateChildEnv(env, acceptanceHome, registryCache, npmConfigFiles);
  const registryEnv = buildCandidateChildEnv(env, acceptanceHome, registryCache, npmConfigFiles);
  const executionEnv = buildCandidateChildEnv(env, acceptanceHome, executionCache, npmConfigFiles);
  const packEnv = buildCandidateChildEnv(env, acceptanceHome, packCache, npmConfigFiles);
  const npmOutput = run(process.execPath, [npmCli, "--version"], "npm version", sourceEnv);
  if (npmOutput.trim() !== REQUIRED_NPM) {
    fail(`npm exactly ${REQUIRED_NPM} is required; got ${npmOutput.trim()}`);
  }
  const observedSourceSha = requireCleanTaggedSource(config, sourceEnv);

  if (!env.GH_TOKEN) fail("GH_TOKEN is required only for the GitHub Release API lookup");
  const release = requireImmutableGitHubRelease(
    config,
    targetContract,
    { ...sourceEnv, GH_TOKEN: env.GH_TOKEN },
  );

  let primaryMetadata = null;
  let mcpMetadata = null;
  let primaryPack = null;
  let mcpPack = null;
  let primaryBefore;
  let mcpBefore;
  let primaryAfter;
  let mcpAfter;
  let mcpOutput;
  let cliOutput;
  let cacheReceipts;
  try {
    primaryBefore = requireCandidateTags(npmCli, registryEnv, "phantom-secrets", config);
    mcpBefore = requireCandidateTags(npmCli, registryEnv, "phantom-secrets-mcp", config);

    let primarySpec;
    let mcpSpec;
    if (config.mode === "prepublication") {
      requireVersionAbsent(npmCli, registryEnv, "phantom-secrets", config.version);
      requireVersionAbsent(npmCli, registryEnv, "phantom-secrets-mcp", config.version);
      const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
      const primary = packLocalPackage(
        npmCli,
        packEnv,
        resolve(repoRoot, "npm"),
        packDirectory,
        "phantom-secrets",
        config.version,
      );
      const mcp = packLocalPackage(
        npmCli,
        packEnv,
        resolve(repoRoot, "npm-mcp"),
        packDirectory,
        "phantom-secrets-mcp",
        config.version,
      );
      primarySpec = primary.spec;
      mcpSpec = mcp.spec;
      primaryPack = primary.receipt;
      mcpPack = mcp.receipt;
    } else {
      primaryMetadata = requirePackageMetadata(
        npmCli,
        registryEnv,
        "phantom-secrets",
        config.version,
        config.primaryIntegrity,
      );
      mcpMetadata = requirePackageMetadata(
        npmCli,
        registryEnv,
        "phantom-secrets-mcp",
        config.version,
        config.mcpIntegrity,
      );
      primarySpec = `phantom-secrets@${config.version}`;
      mcpSpec = `phantom-secrets-mcp@${config.version}`;
    }

    if (
      run("git", ["status", "--porcelain=v1"], "post-pack clean release source", sourceEnv) !== ""
    ) {
      fail("packing changed the exact release source checkout");
    }

    mcpOutput = run(
      process.execPath,
      [
        npmCli,
        "exec",
        "--yes",
        `--package=${mcpSpec}`,
        `--registry=${REGISTRY}`,
        "--",
        "phantom-mcp",
        "--version",
      ],
      `exact MCP ${config.mode} package`,
      executionEnv,
    );
    requireExactVersionLine(mcpOutput, `phantom-mcp ${config.version}`, "MCP package");

    cliOutput = run(
      process.execPath,
      [
        npmCli,
        "exec",
        "--yes",
        `--package=${primarySpec}`,
        `--registry=${REGISTRY}`,
        "--",
        "phantom",
        "--version",
      ],
      `exact CLI ${config.mode} package`,
      executionEnv,
    );
    requireExactVersionLine(cliOutput, `phantom ${config.version}`, "CLI package");

    primaryAfter = requireCandidateTags(npmCli, registryEnv, "phantom-secrets", config);
    mcpAfter = requireCandidateTags(npmCli, registryEnv, "phantom-secrets-mcp", config);
    if (config.mode === "prepublication") {
      requireVersionAbsent(npmCli, registryEnv, "phantom-secrets", config.version);
      requireVersionAbsent(npmCli, registryEnv, "phantom-secrets-mcp", config.version);
    }
    cacheReceipts = requireCacheReceipts(binaryCache, config.version);
  } finally {
    for (const directory of [registryCache, executionCache, packCache, packDirectory]) {
      rmSync(directory, { force: true, recursive: true });
    }
  }

  const receiptPath = env.PHANTOM_NPM_ACCEPTANCE_RECEIPT;
  if (!receiptPath || !isAbsolute(receiptPath)) {
    fail("PHANTOM_NPM_ACCEPTANCE_RECEIPT must be an absolute path");
  }
  writeFileSync(
    receiptPath,
    `${JSON.stringify(
      {
        schema_version: 2,
        accepted: true,
        generated_at: new Date().toISOString(),
        mode: config.mode,
        repository: env.GITHUB_REPOSITORY,
        workflow_ref: workflowIdentity.workflowRef,
        workflow_sha: workflowIdentity.workflowSha,
        trigger_ref: workflowIdentity.githubRef,
        trigger_sha: workflowIdentity.githubSha,
        release_tag: config.releaseTag,
        release_sha: observedSourceSha,
        release,
        version: config.version,
        run_id: env.GITHUB_RUN_ID,
        run_attempt: env.GITHUB_RUN_ATTEMPT,
        run_url: `${env.GITHUB_SERVER_URL}/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}`,
        runner_os: env.RUNNER_OS,
        runner_arch: env.RUNNER_ARCH,
        node_platform: process.platform,
        node_arch: process.arch,
        runner_name: env.RUNNER_NAME,
        runner_image_os: env.ImageOS ?? null,
        runner_image_version: env.ImageVersion ?? null,
        node_version: process.versions.node,
        npm_version: npmOutput.trim(),
        registry: REGISTRY,
        previous_latest_expected: config.previousLatest,
        previous_candidate_expected: config.previousCandidate,
        candidate_tag_name: "release-candidate",
        target: env.PHANTOM_EXPECTED_TARGET,
        primary_metadata: primaryMetadata,
        mcp_metadata: mcpMetadata,
        primary_pack: primaryPack,
        mcp_pack: mcpPack,
        primary_dist_tags_before: primaryBefore,
        mcp_dist_tags_before: mcpBefore,
        primary_dist_tags_after: primaryAfter,
        mcp_dist_tags_after: mcpAfter,
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
    `npm ${config.mode} acceptance passed for ${config.version} on ` +
      `${env.RUNNER_OS}/${env.RUNNER_ARCH} (${process.platform}/${process.arch})`,
  );
}

const isEntrypoint = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isEntrypoint) runNpmCandidateAcceptance();
