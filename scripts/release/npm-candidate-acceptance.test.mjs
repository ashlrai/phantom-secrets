#!/usr/bin/env node

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

import {
  NPM_ACCEPTANCE_TARGETS,
  buildCandidateChildEnv,
  validateAcceptanceConfig,
  validateCandidateTagState,
  validatePackReceipt,
  validateWorkflowIdentity,
} from "./npm-candidate-smoke.mjs";

const repoRoot = resolve(import.meta.dirname, "../..");
const workflow = readFileSync(
  resolve(repoRoot, ".github/workflows/npm-candidate-acceptance.yml"),
  "utf8",
);
const smoke = readFileSync(
  resolve(repoRoot, "scripts/release/npm-candidate-smoke.mjs"),
  "utf8",
);

const sourceSha = "a".repeat(40);
const primaryIntegrity = `sha512-${Buffer.alloc(64, 1).toString("base64")}`;
const mcpIntegrity = `sha512-${Buffer.alloc(64, 2).toString("base64")}`;
const prepublicationEnv = Object.freeze({
  PHANTOM_NPM_ACCEPTANCE_MODE: "prepublication",
  PHANTOM_NPM_ACCEPTANCE_VERSION: "0.7.5",
  PHANTOM_PREVIOUS_NPM_LATEST: "0.6.0",
  PHANTOM_PREVIOUS_NPM_CANDIDATE: "0.7.4",
  PHANTOM_RELEASE_TAG: "v0.7.5",
  PHANTOM_RELEASE_SOURCE_SHA: sourceSha,
  PHANTOM_APPROVED_PRIMARY_INTEGRITY: "",
  PHANTOM_APPROVED_MCP_INTEGRITY: "",
});

test("workflow dispatch exposes both read-only six-host acceptance modes", () => {
  assert.match(workflow, /^on:\n  workflow_dispatch:\n    inputs:/m);
  assert.match(workflow, /default: prepublication/);
  assert.match(workflow, /- prepublication\n          - published-candidate/);
  assert.match(workflow, /^permissions:\n  contents: read$/m);
  assert.doesNotMatch(workflow, /(?:contents|id-token|attestations|packages): write/);
  assert.doesNotMatch(workflow, /npm (?:publish|stage|dist-tag)|gh release create/);
  assert.match(workflow, /ref: v\$\{\{ inputs\.version \}\}/);
  assert.match(workflow, /fetch-depth: 0/);
  assert.match(workflow, /PHANTOM_PREVIOUS_NPM_CANDIDATE: \$\{\{ inputs\.previous_candidate \}\}/);
  assert.match(workflow, /PHANTOM_RELEASE_SOURCE_SHA: \$\{\{ inputs\.release_source_sha \}\}/);
  assert.match(workflow, /npm@11\.15\.0/);
  assert.match(workflow, /node-version: 22\.14\.0/);
  assert.match(workflow, /run: node scripts\/release\/npm-candidate-smoke\.mjs/);
  assert.match(workflow, /path: npm-acceptance-receipt\.json/);

  const matrixTargets = [...workflow.matchAll(/^          - target: (\S+)$/gm)].map((match) => match[1]);
  assert.deepEqual(matrixTargets.sort(), Object.keys(NPM_ACCEPTANCE_TARGETS).sort());
  for (const runner of [
    "macos-15-intel",
    "macos-15",
    "ubuntu-22.04",
    "ubuntu-22.04-arm",
    "windows-latest",
    "windows-11-vs2026-arm",
  ]) {
    assert.match(workflow, new RegExp(`os: ${runner.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
  }
});

test("workflow identity is bound to the tagged release definition and source SHA", () => {
  const config = validateAcceptanceConfig(prepublicationEnv);
  const workflowEnv = {
    GITHUB_REPOSITORY: "ashlrai/phantom-secrets",
    GITHUB_REF: "refs/tags/v0.7.5",
    GITHUB_SHA: sourceSha,
    GITHUB_WORKFLOW_SHA: sourceSha,
    GITHUB_WORKFLOW_REF:
      "ashlrai/phantom-secrets/.github/workflows/npm-candidate-acceptance.yml@refs/tags/v0.7.5",
  };
  assert.deepEqual(validateWorkflowIdentity(workflowEnv, config), {
    githubRef: "refs/tags/v0.7.5",
    githubSha: sourceSha,
    workflowRef: workflowEnv.GITHUB_WORKFLOW_REF,
    workflowSha: sourceSha,
  });
  for (const mutation of [
    { GITHUB_REF: "refs/heads/main" },
    { GITHUB_SHA: "b".repeat(40) },
    { GITHUB_WORKFLOW_SHA: "b".repeat(40) },
    {
      GITHUB_WORKFLOW_REF:
        "ashlrai/phantom-secrets/.github/workflows/npm-candidate-acceptance.yml@refs/heads/main",
    },
  ]) {
    assert.throws(() => validateWorkflowIdentity({ ...workflowEnv, ...mutation }, config));
  }
});

test("candidate children receive only a minimal host environment and empty npm configs", () => {
  const forbidden = {
    GH_TOKEN: "gh-secret",
    GITHUB_TOKEN: "github-secret",
    ACTIONS_RUNTIME_TOKEN: "runtime-secret",
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: "oidc-secret",
    ACTIONS_ID_TOKEN_REQUEST_URL: "https://oidc.invalid/",
    GITHUB_ENV: "/control/env",
    GITHUB_OUTPUT: "/control/output",
    GITHUB_PATH: "/control/path",
    GITHUB_STEP_SUMMARY: "/control/summary",
    GITHUB_STATE: "/control/state",
    GITHUB_EVENT_PATH: "/control/event",
    NODE_AUTH_TOKEN: "node-secret",
    NPM_TOKEN: "npm-secret",
    NPM_CONFIG_USERCONFIG: "/credential-bearing/npmrc",
    npm_config__authToken: "npm-auth-secret",
    AWS_SECRET_ACCESS_KEY: "unrelated-secret",
  };
  const child = buildCandidateChildEnv(
    { PATH: "/usr/bin", TEMP: "/tmp", CI: "true", ...forbidden },
    "/tmp/phantom-home",
    "/tmp/phantom-cache",
    { user: "/tmp/phantom-home/empty-user.npmrc", global: "/tmp/phantom-home/empty-global.npmrc" },
  );
  for (const key of Object.keys(forbidden)) assert.equal(Object.hasOwn(child, key), false, key);
  assert.deepEqual(child, {
    PATH: "/usr/bin",
    TEMP: "/tmp",
    CI: "true",
    HOME: "/tmp/phantom-home",
    USERPROFILE: "/tmp/phantom-home",
    npm_config_cache: "/tmp/phantom-cache",
    npm_config_registry: "https://registry.npmjs.org/",
    npm_config_userconfig: "/tmp/phantom-home/empty-user.npmrc",
    npm_config_globalconfig: "/tmp/phantom-home/empty-global.npmrc",
    npm_config_audit: "false",
    npm_config_fund: "false",
    npm_config_update_notifier: "false",
  });
  assert.match(smoke, /\{ \.\.\.sourceEnv, GH_TOKEN: env\.GH_TOKEN \}/);
});

test("prepublication mode rejects burned-version ambiguity and public integrity inputs", () => {
  assert.deepEqual(validateAcceptanceConfig(prepublicationEnv), {
    mode: "prepublication",
    version: "0.7.5",
    previousLatest: "0.6.0",
    previousCandidate: "0.7.4",
    releaseTag: "v0.7.5",
    releaseSha: sourceSha,
    primaryIntegrity: null,
    mcpIntegrity: null,
  });
  assert.throws(
    () =>
      validateAcceptanceConfig({
        ...prepublicationEnv,
        PHANTOM_APPROVED_PRIMARY_INTEGRITY: primaryIntegrity,
      }),
    /rejects public integrity inputs/,
  );
  assert.throws(
    () =>
      validateCandidateTagState(
        { latest: "0.6.0", "release-candidate": "0.7.5" },
        "prepublication",
        "0.7.5",
        "0.6.0",
        "0.7.4",
        "phantom-secrets",
      ),
    /must remain 0\.7\.4 before publication/,
  );
  assert.deepEqual(
    validateCandidateTagState(
      { latest: "0.6.0", "release-candidate": "0.7.4" },
      "prepublication",
      "0.7.5",
      "0.6.0",
      "0.7.4",
      "phantom-secrets",
    ),
    { latest: "0.6.0", "release-candidate": "0.7.4" },
  );
  assert.match(smoke, /prepublication acceptance requires an unburned version/);
  assert.match(smoke, /packLocalPackage/);
  assert.match(smoke, /pathToFileURL\(tarballPath\)\.href/);
});

test("published-candidate mode requires approved integrity and exact candidate tags", () => {
  const config = validateAcceptanceConfig({
    ...prepublicationEnv,
    PHANTOM_NPM_ACCEPTANCE_MODE: "published-candidate",
    PHANTOM_APPROVED_PRIMARY_INTEGRITY: primaryIntegrity,
    PHANTOM_APPROVED_MCP_INTEGRITY: mcpIntegrity,
  });
  assert.equal(config.mode, "published-candidate");
  assert.equal(config.primaryIntegrity, primaryIntegrity);
  assert.equal(config.mcpIntegrity, mcpIntegrity);
  assert.throws(
    () =>
      validateAcceptanceConfig({
        ...prepublicationEnv,
        PHANTOM_NPM_ACCEPTANCE_MODE: "published-candidate",
      }),
    /requires both approved sha512 integrity values/,
  );
  assert.deepEqual(
    validateCandidateTagState(
      { latest: "0.6.0", "release-candidate": "0.7.5" },
      "published-candidate",
      "0.7.5",
      "0.6.0",
      "0.7.4",
      "phantom-secrets-mcp",
    ),
    { latest: "0.6.0", "release-candidate": "0.7.5" },
  );
  assert.throws(
    () =>
      validateCandidateTagState(
        { latest: "0.6.0", "release-candidate": "0.7.4" },
        "published-candidate",
        "0.7.5",
        "0.6.0",
        "0.7.4",
        "phantom-secrets-mcp",
      ),
    /release-candidate must be exactly/,
  );
});

test("local package receipts enforce the exact five-file wrapper closure", () => {
  const pack = {
    name: "phantom-secrets",
    version: "0.7.5",
    filename: "phantom-secrets-0.7.5.tgz",
    entryCount: 5,
    integrity: primaryIntegrity,
    shasum: "b".repeat(40),
    files: [
      { path: "package.json" },
      { path: "install.js" },
      { path: "bin/cli.js" },
      { path: "README.md" },
      { path: "LICENSE" },
    ],
  };
  assert.equal(validatePackReceipt([pack], "phantom-secrets", "0.7.5"), pack);
  assert.throws(
    () =>
      validatePackReceipt(
        [{ ...pack, entryCount: 6, files: [...pack.files, { path: "unexpected" }] }],
        "phantom-secrets",
        "0.7.5",
      ),
    /closed package contract/,
  );
});

test("receipts bind mode, tag source, release assets, tag snapshots, package bytes, and cache bytes", () => {
  for (const field of [
    "mode: config.mode",
    "workflow_ref: workflowIdentity.workflowRef",
    "workflow_sha: workflowIdentity.workflowSha",
    "trigger_ref: workflowIdentity.githubRef",
    "trigger_sha: workflowIdentity.githubSha",
    "release_sha: observedSourceSha",
    "release,",
    "primary_pack: primaryPack",
    "mcp_pack: mcpPack",
    "primary_dist_tags_before: primaryBefore",
    "primary_dist_tags_after: primaryAfter",
    "previous_candidate_expected: config.previousCandidate",
    "cache_receipts: cacheReceipts",
  ]) {
    assert.match(smoke, new RegExp(field.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
  assert.match(smoke, /const sha256 = createHash\("sha256"\)/);
  assert.match(smoke, /release\.immutable !== true/);
  assert.match(smoke, /requireCacheReceipts\(binaryCache, config\.version\)/);
});
