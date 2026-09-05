#!/usr/bin/env node

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

// Keep signing-readiness contracts on the existing release source-test path
// without changing workflow behavior or permissions.
import "./signing-readiness.test.mjs";
import "./npm-candidate-acceptance.test.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const release = readFileSync(join(repoRoot, ".github/workflows/release.yml"), "utf8");
const ci = readFileSync(join(repoRoot, ".github/workflows/ci.yml"), "utf8");
const releaseBuild = readFileSync(
  join(repoRoot, ".github/workflows/release-build.yml"),
  "utf8"
);
const rehearsal = readFileSync(
  join(repoRoot, ".github/workflows/release-rehearsal.yml"),
  "utf8"
);
const npmCandidateAcceptance = readFileSync(
  join(repoRoot, ".github/workflows/npm-candidate-acceptance.yml"),
  "utf8"
);
const versionParity = readFileSync(
  join(repoRoot, "scripts/release/check-version-parity.mjs"),
  "utf8"
);
const readiness = readFileSync(join(repoRoot, "docs/release-readiness.md"), "utf8");
const npmPublication = readFileSync(join(repoRoot, "docs/npm-publication.md"), "utf8");
const mcpPublication = readFileSync(
  join(repoRoot, "docs/mcp-registry-publication.md"),
  "utf8"
);
const npmPackage = JSON.parse(readFileSync(join(repoRoot, "npm/package.json"), "utf8"));
const npmMcpPackage = JSON.parse(
  readFileSync(join(repoRoot, "npm-mcp/package.json"), "utf8")
);
const npmReadme = readFileSync(join(repoRoot, "npm/README.md"), "utf8");
const npmMcpReadme = readFileSync(join(repoRoot, "npm-mcp/README.md"), "utf8");

const tagOnlyCondition =
  "if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')";

function jobBlock(source, name, nextName) {
  const start = source.indexOf(`\n  ${name}:\n`);
  assert.notEqual(start, -1, `missing ${name} job`);
  const end = nextName ? source.indexOf(`\n  ${nextName}:\n`, start + 1) : source.length;
  assert.notEqual(end, -1, `missing ${nextName} job after ${name}`);
  return source.slice(start, end);
}

function markdownSection(source, heading, nextHeading) {
  const start = source.indexOf(`## ${heading}`);
  assert.notEqual(start, -1, `missing ${heading} section`);
  const end = nextHeading ? source.indexOf(`## ${nextHeading}`, start + 1) : source.length;
  assert.notEqual(end, -1, `missing ${nextHeading} section after ${heading}`);
  return source.slice(start, end);
}

function inspectPack(packageDirectory) {
  const npmExecutable = process.platform === "win32" ? "npm.cmd" : "npm";
  const output = execFileSync(npmExecutable, ["pack", "--dry-run", "--json"], {
    cwd: join(repoRoot, packageDirectory),
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 30_000,
    maxBuffer: 1024 * 1024,
  });
  const packs = JSON.parse(output);
  assert.equal(packs.length, 1, `${packageDirectory} must produce one package`);
  return packs[0];
}

test("manual rehearsal delegates to the shared graph with read-only authority", () => {
  assert.match(rehearsal, /^on:\n  workflow_dispatch:/m);
  assert.match(rehearsal, /^permissions:\n  contents: read$/m);
  assert.match(rehearsal, /uses: \.\/\.github\/workflows\/release-build\.yml/);
  assert.match(rehearsal, /release_tag: \$\{\{ inputs\.release_tag \}\}/);
  assert.doesNotMatch(rehearsal, /(?:contents|attestations|id-token): write/);
  assert.doesNotMatch(rehearsal, /environment:/);
  assert.doesNotMatch(rehearsal, /(?:npm|cargo|mcp-publisher) publish|gh release/);
});

test("release defaults and lockfiles are part of the exact version parity contract", () => {
  assert.match(rehearsal, /default: v0\.7\.8/);
  assert.match(
    npmCandidateAcceptance,
    /^      version:\n[\s\S]*?^        default: 0\.7\.8$/m
  );
  assert.match(versionParity, /json\("apps\/web\/package-lock\.json"\)/);
  assert.match(versionParity, /Hosted web lockfile root/);
  assert.match(versionParity, /README source badge/);
  assert.match(versionParity, /Roadmap release/);
  assert.match(versionParity, /phantom-release-version/);
  assert.match(versionParity, /Current changelog candidate/);
  assert.match(versionParity, /npm candidate acceptance default/);
  assert.equal(
    execFileSync(
      process.execPath,
      [join(repoRoot, "scripts/release/check-version-parity.mjs"), "v0.7.8"],
      { cwd: repoRoot, encoding: "utf8" }
    ).trim(),
    "release version parity passed: 0.7.8 across 19 surfaces and 12 crates"
  );
});

test("web dependency audits use the exact supported npm CLI and stay fail closed", () => {
  for (const [name, workflow] of [
    ["CI", ci],
    ["release build", releaseBuild],
  ]) {
    assert.match(
      workflow,
      /^  PHANTOM_NPM_AUDIT_VERSION: 11\.15\.0$/m,
      `${name} must pin the npm audit client`,
    );
    assert.match(
      workflow,
      /run: npm ci --no-audit/,
      `${name} must leave advisory checking to the exact audit client`,
    );
    assert.match(
      workflow,
      /npm install \\\n[\s\S]*?--prefix "\$\{RUNNER_TEMP\}\/phantom-npm-audit"[\s\S]*?--ignore-scripts[\s\S]*?--no-audit[\s\S]*?"npm@\$\{PHANTOM_NPM_AUDIT_VERSION\}"/,
      `${name} must install the audit client without lifecycle scripts`,
    );
    assert.match(
      workflow,
      /"\$\{RUNNER_TEMP\}\/phantom-npm-audit\/node_modules\/\.bin\/npm"\s+audit --omit=dev --audit-level=moderate/,
      `${name} must fail on moderate-or-higher production advisories`,
    );
    assert.doesNotMatch(
      workflow,
      /^\s*run: npm audit --omit=dev --audit-level=moderate$/m,
      `${name} must not fall back to the runner-bundled npm audit client`,
    );
  }
});

test("shared graph validates the exact tag before building and keeps native acceptance exact", () => {
  assert.match(releaseBuild, /^  workflow_call:\n    inputs:\n      release_tag:/m);
  assert.match(releaseBuild, /^permissions:\n  contents: read$/m);
  assert.doesNotMatch(releaseBuild, /^  (?:push|workflow_dispatch):/m);
  assert.match(
    releaseBuild,
    /PHANTOM_RELEASE_TAG: \$\{\{ inputs\.release_tag \}\}/
  );

  const parity = releaseBuild.indexOf(
    'node scripts/release/check-version-parity.mjs "$PHANTOM_RELEASE_TAG"'
  );
  const buildJob = releaseBuild.indexOf("\n  build:\n");
  assert.ok(parity > 0 && parity < buildJob, "version/tag validation must precede builds");

  const build = jobBlock(releaseBuild, "build", "native-acceptance");
  assert.match(build, /strategy:\n      fail-fast: false/);
  assert.match(
    build,
    /- name: Package \(Windows\)\n        if: runner\.os == 'Windows'\n        shell: pwsh\n        run: \|\n          \$ErrorActionPreference = 'Stop'\n          \$PSNativeCommandUseErrorActionPreference = \$true/,
    "Windows packaging must use the PowerShell fail-fast statements under pwsh",
  );
  const native = jobBlock(releaseBuild, "native-acceptance", "verify-artifacts");
  assert.match(native, /needs: build/);
  assert.match(native, /strategy:\n      fail-fast: false/);
  assert.match(native, /run: node scripts\/release\/native-release-smoke\.mjs/);
  assert.match(native, /run: node scripts\/release\/native-installer-acceptance\.mjs/);
  assert.match(native, /Install the exact archive and prove transaction rollback/);
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
    assert.match(native, new RegExp(`run: ${command.replaceAll(".", "\\.")}`));
  }
  assert.doesNotMatch(native, /run: \|\n(?:\s+node npm(?:-mcp)?\/test\/[^\n]+\n){2,}/);
  assert.match(native, /node scripts\/release\/npm-wrapper-native-acceptance\.mjs/);
  assert.doesNotMatch(native, /(?:npm|cargo|mcp-publisher) publish|gh release/);
});

test("rehearsal reaches checksum and SBOM verification without publication authority", () => {
  const verify = jobBlock(releaseBuild, "verify-artifacts");
  assert.match(verify, /needs: \[build, native-acceptance\]/);
  assert.match(verify, /^    permissions:\n      contents: read$/m);
  assert.match(verify, /Generate SHA-256 checksums/);
  assert.match(verify, /node scripts\/release\/verify-release-artifacts\.mjs artifacts/);
  assert.match(verify, /name: verified-release-bundle/);
  assert.doesNotMatch(verify, /(?:contents|attestations|id-token): write/);
  assert.doesNotMatch(verify, /environment:/);
  assert.doesNotMatch(releaseBuild, /(?:contents|attestations|id-token): write/);
  assert.doesNotMatch(releaseBuild, /(?:npm|cargo|mcp-publisher) publish|gh release/);
});

test("attestation verification gates release approval and remains tag-push-only", () => {
  const attest = jobBlock(release, "attest", "verify-attestations");
  const verifyAttestations = jobBlock(
    release,
    "verify-attestations",
    "release"
  );
  const publish = jobBlock(release, "release");
  assert.match(attest, new RegExp(tagOnlyCondition.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.match(
    verifyAttestations,
    new RegExp(tagOnlyCondition.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
  );
  assert.match(publish, new RegExp(tagOnlyCondition.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.match(attest, /attestations: write/);
  assert.match(attest, /id-token: write/);
  assert.match(verifyAttestations, /needs: attest/);
  assert.match(
    verifyAttestations,
    /^    permissions:\n      contents: read\n      attestations: read$/m
  );
  assert.match(
    verifyAttestations,
    /node scripts\/release\/verify-release-artifacts\.mjs artifacts/
  );
  assert.equal(
    verifyAttestations.match(/gh attestation verify "\$archive_path"/g)?.length,
    2,
    "each of the six archives must verify provenance and SPDX attestations"
  );
  assert.match(
    verifyAttestations,
    /--predicate-type "https:\/\/spdx\.dev\/Document\/v2\.3"/
  );
  assert.match(verifyAttestations, /--signer-digest "\$GITHUB_SHA"/);
  assert.match(verifyAttestations, /--source-ref "\$GITHUB_REF"/);
  assert.match(verifyAttestations, /--source-digest "\$GITHUB_SHA"/);
  assert.match(verifyAttestations, /--deny-self-hosted-runners/);
  assert.doesNotMatch(
    verifyAttestations,
    /(?:contents|attestations|id-token): write|environment:/
  );
  assert.match(publish, /needs: verify-attestations/);
  assert.match(publish, /environment:\n      name: release/);
  assert.match(publish, /contents: write/);
  assert.match(release, /^  build-and-verify:\n(?:.|\n)*?uses: \.\/\.github\/workflows\/release-build\.yml/m);
  assert.match(release, /release_tag: \$\{\{ github\.ref_name \}\}/);
  assert.match(attest, /needs: build-and-verify/);
  assert.match(release, /^on:\n  push:\n    tags:\n      - 'v\*'$/m);
  assert.doesNotMatch(release, /^  workflow_call:/m);
});

test("tag binding remains mandatory for tag pushes and absent from rehearsal caller", () => {
  const binding = releaseBuild.indexOf("- name: Verify immutable annotated release tag binding");
  assert.ok(binding > 0, "missing tag-binding step");
  const following = releaseBuild.slice(binding, binding + 500);
  assert.match(following, new RegExp(tagOnlyCondition.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.match(following, /verify-github-tag-binding\.mjs/);
  assert.doesNotMatch(rehearsal, /verify-github-tag-binding|refs\/tags/);
});

test("npm and MCP distribution metadata and runbooks remain publication-safe", () => {
  for (const packageJson of [npmPackage, npmMcpPackage]) {
    assert.deepEqual(packageJson.publishConfig, {
      access: "public",
      registry: "https://registry.npmjs.org/",
    });
  }

  for (const readme of [npmReadme, npmMcpReadme]) {
    assert.match(readme, /This wrapper is version `0\.7\.8`/);
    assert.match(readme, /npm view phantom-secrets(?:-mcp)?@0\.7\.8/);
    assert.match(readme, /releases\/tag\/v0\.7\.8/);
    assert.match(readme, /do not prove|does not prove/);
    assert.doesNotMatch(readme, /v0\.7\.3|older release track|Current main/);
  }

  assert.match(readiness, /\(cd npm && npm pack --dry-run\)/);
  assert.match(readiness, /\(cd npm-mcp && npm pack --dry-run\)/);
  assert.doesNotMatch(readiness, /npm --prefix npm(?:-mcp)? pack --dry-run/);
  assert.match(readiness, /\[npm publication runbook\]\(npm-publication\.md\)/);
  assert.match(
    readiness,
    /\[MCP Registry publication runbook\]\(mcp-registry-publication\.md\)/
  );
  assert.match(readiness, /stage both under `release-candidate`/);
  assert.match(readiness, /six-target npm-channel\s+acceptance gate/);
  assert.match(readiness, /MCP\s+wrapper to `latest` first and the primary CLI to `latest` last/);

  const npmPlan = markdownSection(
    npmPublication,
    "Read-only source and package plan",
    "Recompute and stage both candidates"
  );
  const mcpPlan = markdownSection(
    mcpPublication,
    "Read-only source and registry plan",
    "Human-approved interactive effect"
  );
  const npmStage = markdownSection(
    npmPublication,
    "Recompute and stage both candidates",
    "Review both stages before approval"
  );
  const mcpEffect = markdownSection(
    mcpPublication,
    "Human-approved interactive effect",
    "Reconcile the public effect"
  );
  const npmPromotion = markdownSection(
    npmPublication,
    "Promote default tags after acceptance",
    "Partial failure and recovery"
  );
  const mcpReconcile = markdownSection(
    mcpPublication,
    "Reconcile the public effect",
    "Partial failure and recovery"
  );
  assert.doesNotMatch(npmPlan, /npm publish/);
  assert.doesNotMatch(mcpPlan, /mcp-publisher"? publish/);
  assert.doesNotMatch(npmPublication, /\bnpm\s+publish\b/);
  assert.match(npmPublication, /## Partial failure and recovery/);
  assert.match(mcpPublication, /## Partial failure and recovery/);
  assert.match(npmPublication, /Never put an npm credential or one-time password/);
  assert.match(mcpPublication, /Never pass an MCP Registry token/);
  assert.match(mcpPublication, /test "\$\(uname -s\)-\$\(uname -m\)" = "Linux-x86_64"/);
  assert.match(npmPublication, /Node\.js `22\.14\.0` or later/);
  assert.match(npmPublication, /npm CLI `11\.15\.0` or later/);
  assert.match(npmStage, /NPM_STAGE_DIR="\$\(mktemp -d\)"/);
  assert.match(npmStage, /chmod 700 "\$\{NPM_STAGE_DIR\}"/);
  assert.match(npmStage, /trap cleanup_npm_stage EXIT HUP INT TERM/);
  assert.match(
    npmStage,
    /\(cd npm && npm pack --json --pack-destination "\$\{NPM_STAGE_DIR\}"\)/
  );
  assert.match(
    npmStage,
    /\(cd npm-mcp && npm pack --json --pack-destination "\$\{NPM_STAGE_DIR\}"\)/
  );
  assert.match(npmStage, /PRIMARY_TARBALL="\$\{NPM_STAGE_DIR\}\/phantom-secrets-\$\{VERSION\}\.tgz"/);
  assert.match(npmStage, /MCP_TARBALL="\$\{NPM_STAGE_DIR\}\/phantom-secrets-mcp-\$\{VERSION\}\.tgz"/);
  assert.match(npmStage, /packs\[0\]\.filename !== `\$\{name\}-\$\{version\}\.tgz`/);
  assert.match(npmStage, /packs\[0\]\.entryCount !== 5/);
  assert.match(npmStage, /packs\[0\]\.integrity !== approvedIntegrity/);
  assert.equal(
    npmStage.match(/npm pack --json --pack-destination/g)?.length,
    2,
    "each package must be packed exactly once for staging"
  );
  assert.match(
    npmStage,
    /npm stage publish "\$\{PRIMARY_TARBALL\}" --tag release-candidate \\\n  --registry=https:\/\/registry\.npmjs\.org\//
  );
  assert.match(
    npmStage,
    /npm stage publish "\$\{MCP_TARBALL\}" --tag release-candidate \\\n  --registry=https:\/\/registry\.npmjs\.org\//
  );
  assert.doesNotMatch(npmStage, /npm stage publish --tag release-candidate/);
  assert.doesNotMatch(npmStage, /npm stage publish (?:\.|npm|npm-mcp) --tag/);
  assert.equal(
    npmStage.match(/^npm stage publish /gm)?.length,
    2,
    "only the two explicit reviewed tarballs may be staged"
  );
  assert.match(npmPublication, /npm stage list phantom-secrets --json/);
  assert.match(npmPublication, /npm stage list phantom-secrets-mcp --json/);
  assert.match(npmPublication, /npm stage view "\$\{PRIMARY_STAGE_ID\}"/);
  assert.match(npmPublication, /npm stage view "\$\{MCP_STAGE_ID\}"/);
  assert.match(npmPublication, /npm stage download "\$\{PRIMARY_STAGE_ID\}"/);
  assert.match(npmPublication, /npm stage download "\$\{MCP_STAGE_ID\}"/);
  assert.match(npmPublication, /npm stage approve "\$\{MCP_STAGE_ID\}"/);
  assert.match(npmPublication, /npm stage approve "\$\{PRIMARY_STAGE_ID\}"/);
  assert.match(npmPublication, /Enter 2FA only at npm's interactive prompt/);
  assert.match(npmPublication, /all six targets/);
  assert.match(npmPublication, /\| macOS x64 \| `macos-15-intel` \|/);
  assert.match(npmPublication, /\| macOS arm64 \| `macos-15` \|/);
  assert.match(npmPublication, /\| GNU Linux x64 \| `ubuntu-22\.04` \|/);
  assert.match(npmPublication, /\| GNU Linux arm64 \| `ubuntu-22\.04-arm` \|/);
  assert.match(npmPublication, /\| Windows x64 \| `windows-latest` \|/);
  assert.match(npmPublication, /\| Windows arm64 \| `windows-11-vs2026-arm` \|/);
  assert.match(npmPublication, /--package=phantom-secrets-mcp@0\.7\.8/);
  assert.match(npmPublication, /--package=phantom-secrets@0\.7\.8/);
  assert.match(npmPublication, /dist\.attestations/);
  assert.match(npmPublication, /SHA-512 SRI/);
  assert.match(npmPublication, /verify-github-tag-binding\.mjs/);
  assert.match(npmPublication, /origin is not canonical/);
  assert.match(npmPublication, /does not currently contain or prove that protected npm staging/);
  assert.match(npmPublication, /disallow tokens/);

  const primaryPack = npmStage.indexOf(
    '(cd npm && npm pack --json --pack-destination "${NPM_STAGE_DIR}")'
  );
  const mcpPack = npmStage.indexOf(
    '(cd npm-mcp && npm pack --json --pack-destination "${NPM_STAGE_DIR}")'
  );
  const sourceRecheck = npmStage.indexOf(
    'test "${SOURCE_SHA}" = "$(git rev-parse HEAD)"'
  );
  const tagRecheck = npmStage.indexOf(
    'node scripts/release/verify-github-tag-binding.mjs "${TAG}" "${SOURCE_SHA}"'
  );
  const primaryStage = npmStage.indexOf(
    'npm stage publish "${PRIMARY_TARBALL}" --tag release-candidate'
  );
  const mcpStage = npmStage.indexOf(
    'npm stage publish "${MCP_TARBALL}" --tag release-candidate'
  );
  const mcpApprove = npmPublication.indexOf('npm stage approve "${MCP_STAGE_ID}"');
  const mcpPublicJson = npmPublication.indexOf('MCP_PUBLIC_JSON="$(npm view');
  const mcpPublicPack = npmPublication.indexOf('MCP_PUBLIC_PACK_JSON="$(npm pack');
  const mcpPublicProvenanceStop = npmPublication.indexOf(
    "Stop here before approving the primary stage. Require the MCP public metadata"
  );
  const primaryApprove = npmPublication.indexOf('npm stage approve "${PRIMARY_STAGE_ID}"');
  assert.ok(
    [
      primaryPack,
      mcpPack,
      sourceRecheck,
      tagRecheck,
      primaryStage,
      mcpStage,
      mcpApprove,
      mcpPublicJson,
      mcpPublicPack,
      mcpPublicProvenanceStop,
      primaryApprove,
    ].every((index) => index >= 0),
    "explicit tarballs, source rechecks, stages, and approvals are mandatory"
  );
  assert.ok(
    Math.max(primaryPack, mcpPack) < sourceRecheck &&
      sourceRecheck < tagRecheck &&
      tagRecheck < Math.min(primaryStage, mcpStage) &&
      Math.max(primaryStage, mcpStage) < mcpApprove &&
      mcpApprove < mcpPublicJson &&
      mcpPublicJson < mcpPublicPack &&
      mcpPublicPack < mcpPublicProvenanceStop &&
      mcpPublicProvenanceStop < primaryApprove,
    "pack once, recheck source/tag, stage both tarballs, approve MCP, reconcile its public bytes/provenance, then approve primary"
  );

  const mcpLatest = npmPublication.indexOf(
    'npm dist-tag add "phantom-secrets-mcp@${VERSION}" latest'
  );
  const primaryLatest = npmPublication.indexOf(
    'npm dist-tag add "phantom-secrets@${VERSION}" latest'
  );
  const mcpCandidateRemoval = npmPublication.indexOf(
    "npm dist-tag rm phantom-secrets-mcp release-candidate"
  );
  const primaryCandidateRemoval = npmPublication.indexOf(
    "npm dist-tag rm phantom-secrets release-candidate"
  );
  assert.ok(
    [mcpLatest, primaryLatest, mcpCandidateRemoval, primaryCandidateRemoval].every(
      (index) => index >= 0
    ),
    "missing required dist-tag promotion or cleanup command"
  );
  assert.ok(
    mcpLatest < primaryLatest &&
      primaryLatest < mcpCandidateRemoval &&
      mcpCandidateRemoval < primaryCandidateRemoval,
    "promote MCP first, primary last, then remove candidate tags"
  );

  const firstMcpTagQuery = npmPromotion.indexOf(
    'MCP_TAGS_JSON="$(npm view phantom-secrets-mcp dist-tags --json'
  );
  const firstPrimaryTagQuery = npmPromotion.indexOf(
    'PRIMARY_TAGS_JSON="$(npm view phantom-secrets dist-tags --json'
  );
  const firstTagGuard = npmPromotion.indexOf(
    'mt.latest!==oldM||pt.latest!==oldP||mt["release-candidate"]!==v||pt["release-candidate"]!==v'
  );
  const guardedMcpLatest = npmPromotion.indexOf(
    'npm dist-tag add "phantom-secrets-mcp@${VERSION}" latest'
  );
  const secondMcpTagQuery = npmPromotion.indexOf(
    'MCP_TAGS_JSON="$(npm view phantom-secrets-mcp dist-tags --json',
    firstMcpTagQuery + 1
  );
  const secondPrimaryTagQuery = npmPromotion.indexOf(
    'PRIMARY_TAGS_JSON="$(npm view phantom-secrets dist-tags --json',
    firstPrimaryTagQuery + 1
  );
  const secondTagGuard = npmPromotion.indexOf(
    'mt.latest!==v||pt.latest!==oldP||mt["release-candidate"]!==v||pt["release-candidate"]!==v'
  );
  const guardedPrimaryLatest = npmPromotion.indexOf(
    'npm dist-tag add "phantom-secrets@${VERSION}" latest'
  );
  assert.ok(
    [
      firstMcpTagQuery,
      firstPrimaryTagQuery,
      firstTagGuard,
      guardedMcpLatest,
      secondMcpTagQuery,
      secondPrimaryTagQuery,
      secondTagGuard,
      guardedPrimaryLatest,
    ].every((index) => index >= 0),
    "both dist-tag maps and expected candidate/latest states must guard each promotion"
  );
  assert.ok(
    firstMcpTagQuery < firstPrimaryTagQuery &&
      firstPrimaryTagQuery < firstTagGuard &&
      firstTagGuard < guardedMcpLatest &&
      guardedMcpLatest < secondMcpTagQuery &&
      secondMcpTagQuery < secondPrimaryTagQuery &&
      secondPrimaryTagQuery < secondTagGuard &&
      secondTagGuard < guardedPrimaryLatest,
    "reconcile both tag maps immediately before MCP-first and primary-last promotion"
  );

  const firstRemovalMcpQuery = npmPromotion.indexOf(
    'MCP_TAGS_JSON="$(npm view phantom-secrets-mcp dist-tags --json',
    guardedPrimaryLatest + 1
  );
  const firstRemovalPrimaryQuery = npmPromotion.indexOf(
    'PRIMARY_TAGS_JSON="$(npm view phantom-secrets dist-tags --json',
    guardedPrimaryLatest + 1
  );
  const firstRemovalGuard = npmPromotion.indexOf(
    'mt.latest!==v||pt.latest!==v||mt["release-candidate"]!==v||pt["release-candidate"]!==v'
  );
  const guardedMcpRemoval = npmPromotion.indexOf(
    "npm dist-tag rm phantom-secrets-mcp release-candidate"
  );
  const secondRemovalMcpQuery = npmPromotion.indexOf(
    'MCP_TAGS_JSON="$(npm view phantom-secrets-mcp dist-tags --json',
    guardedMcpRemoval + 1
  );
  const secondRemovalPrimaryQuery = npmPromotion.indexOf(
    'PRIMARY_TAGS_JSON="$(npm view phantom-secrets dist-tags --json',
    guardedMcpRemoval + 1
  );
  const secondRemovalGuard = npmPromotion.indexOf(
    'Object.hasOwn(mt,"release-candidate")||pt["release-candidate"]!==v'
  );
  const guardedPrimaryRemoval = npmPromotion.indexOf(
    "npm dist-tag rm phantom-secrets release-candidate"
  );
  assert.ok(
    [
      firstRemovalMcpQuery,
      firstRemovalPrimaryQuery,
      firstRemovalGuard,
      guardedMcpRemoval,
      secondRemovalMcpQuery,
      secondRemovalPrimaryQuery,
      secondRemovalGuard,
      guardedPrimaryRemoval,
    ].every((index) => index >= 0),
    "fresh exact latest/candidate state must guard each candidate-tag removal"
  );
  assert.ok(
    firstRemovalMcpQuery < firstRemovalPrimaryQuery &&
      firstRemovalPrimaryQuery < firstRemovalGuard &&
      firstRemovalGuard < guardedMcpRemoval &&
      guardedMcpRemoval < secondRemovalMcpQuery &&
      secondRemovalMcpQuery < secondRemovalPrimaryQuery &&
      secondRemovalPrimaryQuery < secondRemovalGuard &&
      secondRemovalGuard < guardedPrimaryRemoval,
    "requery both tag maps immediately before each sequential candidate removal"
  );

  assert.match(mcpPublication, /MCP_HOME="\$\(mktemp -d\)"/);
  assert.match(mcpPublication, /set -euo pipefail/);
  assert.match(mcpPublication, /chmod 700 "\$\{MCP_HOME\}"/);
  assert.match(mcpPublication, /trap cleanup_mcp_publish EXIT HUP INT TERM/);
  assert.match(mcpPublication, /timeout 300s/);
  assert.match(mcpPublication, /timeout 120s/);
  assert.match(mcpPublication, /timeout 45s curl/);
  assert.match(
    mcpPublication,
    /login github \\\n  --registry="\$\{MCP_REGISTRY_URL\}"/
  );
  assert.equal(
    mcpPublication.match(/--registry="\$\{MCP_REGISTRY_URL\}"/g)?.length,
    1,
    "only login accepts the explicit MCP Registry flag"
  );
  assert.match(
    mcpPublication,
    /mcp-publisher" logout >\/dev\/null 2>&1/
  );
  const logoutCwd = mcpPublication.indexOf('cd "${MCP_HOME}" || exit 1');
  const publisherLogout = mcpPublication.indexOf('mcp-publisher" logout');
  assert.ok(
    logoutCwd >= 0 && publisherLogout >= 0 && logoutCwd < publisherLogout,
    "publisher logout must run from the ephemeral MCP home"
  );
  assert.match(mcpPublication, /Logout deletes local credential material; it does not\s+revoke an already issued registry token/);
  assert.match(
    mcpPublication,
    /WARNING: MCP publisher logout failed; record logout_failed=true externally/
  );
  assert.match(mcpPublication, /No automatic receipt survives\s+cleanup/);
  assert.equal(
    mcpPublication.match(
      /env HOME="\$\{MCP_HOME\}" timeout 60s "\$\{PUBLISHER_DIR\}\/mcp-publisher" \\\n  validate mcp-registry\/server\.json/g
    )?.length,
    3,
    "all pinned manifest validations must ignore normal-home publisher state"
  );
  assert.doesNotMatch(
    mcpPublication,
    /(?:^|\n)timeout 60s "\$\{PUBLISHER_DIR\}\/mcp-publisher" \\\n  validate/
  );
  assert.match(
    mcpPublication,
    /mcp-publisher" publish mcp-registry\/server\.json\n/
  );
  assert.doesNotMatch(
    mcpPublication,
    /(?:logout|validate mcp-registry\/server\.json|publish mcp-registry\/server\.json)[^\n]*\\?\n?\s*--registry/
  );
  assert.match(mcpPublication, /\?include_deleted=true/);
  assert.match(mcpPublication, /--output "\$\{MCP_BODY\}" --write-out '%\{http_code\}'/);
  assert.match(mcpPublication, /does not\s+currently contain or prove that MCP publication workflow/);
  assert.match(mcpPublication, /verify-github-tag-binding\.mjs/);
  assert.match(mcpPublication, /origin is not canonical/);
  assert.match(mcpPublication, /mcp-publisher" publish mcp-registry\/server\.json/);
  assert.match(
    mcpReconcile,
    /jq -S 'del\(\._meta\["io\.modelcontextprotocol\.registry\/official"\]\)/
  );
  assert.match(mcpReconcile, /jq -S '\.server \|/);
  assert.match(
    mcpReconcile,
    /cmp --silent "\$\{REVIEWED_SERVER_NORMALIZED\}" "\$\{PUBLIC_SERVER_NORMALIZED\}"/
  );
  assert.match(
    mcpReconcile,
    /\._meta\["io\.modelcontextprotocol\.registry\/official"\]\.status == "active"/
  );
  assert.doesNotMatch(mcpReconcile, /\.server\.(?:name|version|repository|packages)\b/);
  const deepCompare = mcpReconcile.indexOf('cmp --silent "${REVIEWED_SERVER_NORMALIZED}"');
  const activeStatus = mcpReconcile.indexOf(
    '._meta["io.modelcontextprotocol.registry/official"].status == "active"'
  );
  assert.ok(
    deepCompare >= 0 && activeStatus >= 0 && deepCompare < activeStatus,
    "deep-compare every immutable manifest field before checking active status separately"
  );

  const manifestRehash = mcpEffect.indexOf(
    'sha256sum mcp-registry/server.json | awk \'{print $1}\''
  );
  const manifestRevalidate = mcpEffect.indexOf(
    'validate mcp-registry/server.json'
  );
  const registryLogin = mcpEffect.indexOf('mcp-publisher" login github');
  const registryPublish = mcpEffect.indexOf(
    'mcp-publisher" publish mcp-registry/server.json'
  );
  const postLoginClean = mcpEffect.indexOf(
    'test -z "$(git status --porcelain=v1)"',
    registryLogin + 1
  );
  const postLoginSource = mcpEffect.indexOf(
    'test "${SOURCE_SHA}" = "$(git rev-parse HEAD)"',
    registryLogin + 1
  );
  const postLoginTag = mcpEffect.indexOf(
    'verify-github-tag-binding.mjs "${TAG}" "${SOURCE_SHA}"',
    registryLogin + 1
  );
  const postLoginRehash = mcpEffect.indexOf(
    'sha256sum mcp-registry/server.json | awk \'{print $1}\'',
    registryLogin + 1
  );
  const postLoginRevalidate = mcpEffect.indexOf(
    'validate mcp-registry/server.json',
    registryLogin + 1
  );
  assert.ok(
    [
      manifestRehash,
      manifestRevalidate,
      registryLogin,
      postLoginClean,
      postLoginSource,
      postLoginTag,
      postLoginRehash,
      postLoginRevalidate,
      registryPublish,
    ].every((index) => index >= 0),
    "MCP effect requires pre-login and post-login source/digest validation"
  );
  assert.ok(
    manifestRehash < manifestRevalidate &&
      manifestRevalidate < registryLogin &&
      registryLogin < postLoginClean &&
      postLoginClean < postLoginSource &&
      postLoginSource < postLoginTag &&
      postLoginTag < postLoginRehash &&
      postLoginRehash < postLoginRevalidate &&
      postLoginRevalidate < registryPublish,
    "repeat clean source, digest, and HOME-bound validation after login immediately before publish"
  );

  const mcpReconciliation = mcpPublication.indexOf("## Reconcile the public effect");
  const mcpInteractiveEffect = mcpPublication.indexOf(
    "## Human-approved interactive effect"
  );
  assert.ok(
    mcpReconciliation >= 0 &&
      mcpInteractiveEffect >= 0 &&
      mcpInteractiveEffect < mcpReconciliation,
    "MCP publication must be followed by a bounded public-state reconciliation"
  );
});

test("npm package contents remain the exact five reviewed files", () => {
  const expectedFiles = ["LICENSE", "README.md", "bin/cli.js", "install.js", "package.json"];

  for (const [directory, packageName] of [
    ["npm", "phantom-secrets"],
    ["npm-mcp", "phantom-secrets-mcp"],
  ]) {
    const pack = inspectPack(directory);
    assert.equal(pack.name, packageName);
    assert.equal(pack.version, "0.7.8");
    assert.equal(pack.entryCount, 5);
    assert.deepEqual(
      pack.files.map(({ path }) => path).sort(),
      expectedFiles
    );
  }
});
