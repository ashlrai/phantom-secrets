#!/usr/bin/env node

import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

// Keep signing-readiness contracts on the existing release source-test path
// without changing workflow behavior or permissions.
import "./signing-readiness.test.mjs";
import "./qualify-full-ci.test.mjs";
import "./npm-candidate-acceptance.test.mjs";
import { loadSources } from "../freshness/sources.mjs";
import { assertDependencyIndexClean } from "./check-dependency-index.mjs";
import { assertPowershellCandidate, assertShellCandidate } from "./check-powershell-candidate.mjs";

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

// Source-candidate commands track source metadata, never a dated public receipt.
const cargo = readFileSync(join(repoRoot, "Cargo.toml"), "utf8");
const workspaceSections = cargo.split(/^\[workspace\.package\]\s*$/m);
assert.equal(workspaceSections.length, 2, "one Cargo workspace.package section");
const workspacePackage = workspaceSections[1].split(/^\[/m)[0];
const versionRows = [...workspacePackage.matchAll(/^version\s*=\s*"([^"]+)"\s*$/gm)];
assert.equal(versionRows.length, 1, "one Cargo source version");
const { version: sourceVersion } = loadSources(repoRoot);
assert.equal(versionRows[0][1], sourceVersion, "unique workspace row matches canonical source metadata");

function candidateCommands(version) {
  return [
    ["gh workflow run release-rehearsal.yml", `gh workflow run release-rehearsal.yml -f release_tag=v${version}`],
    ["node scripts/release/pre-tag-preflight.mjs", `node scripts/release/pre-tag-preflight.mjs v${version} REHEARSAL_RUN_ID_OR_URL`],
    ["node scripts/release/check-version-parity.mjs", `node scripts/release/check-version-parity.mjs v${version}`],
    ["./scripts/publish-crates.sh --verify-only", `./scripts/publish-crates.sh --verify-only --version ${version}`],
    ["./scripts/publish-crates.sh --dry-run", `./scripts/publish-crates.sh --dry-run --version ${version}`],
    ["PHANTOM_PUBLISH_CONFIRM=", `PHANTOM_PUBLISH_CONFIRM=publish-phantom-secrets-${version} \\`],
    ["./scripts/publish-crates.sh --publish", `./scripts/publish-crates.sh --publish --version ${version}`],
  ];
}

function assertCandidateExamples(document, version) {
  const lines = document.split(/\r?\n/).map((line) => line.trim());
  for (const [prefix, expected] of candidateCommands(version)) {
    assert.deepEqual(lines.filter((line) => line.startsWith(prefix)), [expected],
      `one exact current-source candidate example: ${prefix}`);
  }
}

test("candidate runbook examples reject stale, missing and duplicate commands", () => {
  assertCandidateExamples(readiness, sourceVersion);
  for (const [, expected] of candidateCommands(sourceVersion)) {
    assert.throws(() => assertCandidateExamples(readiness.replace(expected,
      expected.replace(sourceVersion, "99.98.97")), sourceVersion), /current-source candidate/);
    assert.throws(() => assertCandidateExamples(readiness.replace(expected, ""), sourceVersion), /current-source candidate/);
    assert.throws(() => assertCandidateExamples(readiness + `\n${expected}\n`, sourceVersion), /current-source candidate/);
  }
  assertCandidateExamples(readiness.replaceAll(sourceVersion, "99.98.97"), "99.98.97");
});

function assertReleaseEligibilityWarnings(document) {
  const warnings = [
    /Source-version agreement does not establish release eligibility or permission to publish\./,
    /the annotated `v0\.8\.0` tag already exists and\s+peels to `1a881e82dad94f766d15c1caea43139b7022e817`/,
    /A tag reservation does not\s+prove a published GitHub Release or package\./,
    /illustrative fail-closed check: it must reject this reserved identity\./,
    /Do not reuse, delete, move, or overwrite that tag\./,
    /separately reviewed unreserved version, matching source metadata,/,
    /this guide selects no such version\./,
    /linked npm and MCP Registry runbooks retain version-specific `0\.7\.8`\s+examples/,
    new RegExp("are not current `" + sourceVersion.replaceAll(".", "\\.") + "` source facts or copy-ready instructions for this candidate\\."),
    /Do not mechanically execute or substitute versions in those recipes\./,
    /reconcile the exact approved source, tag, package versions,\s+manifest, acceptance receipts, and publication authorization/,
  ];
  for (const warning of warnings) assert.match(document, warning, "release eligibility warning");
  assert.ok(document.indexOf("Source-version agreement") <
    document.indexOf("gh workflow run release-rehearsal.yml"), "qualify examples before the first command");
  return warnings;
}

test("source examples retain reserved-tag and older linked-recipe warnings", () => {
  const warnings = assertReleaseEligibilityWarnings(readiness);
  for (const warning of warnings) {
    assert.throws(() => assertReleaseEligibilityWarnings(readiness.replace(warning, "")),
      /release eligibility warning/);
  }
  // This is a dated reservation receipt, not a live remote lookup or future-version claim.
  assert.throws(() => assertReleaseEligibilityWarnings(readiness.replace(
    "it must reject this reserved identity", "it may reuse this reserved identity")), /release eligibility warning/);
});

test("dependency index validation rejects tracked installations, not similar names", () => {
  for (const path of ["node_modules", "apps/web/node_modules", "node_modules/a.js",
    "nested/node_modules/pkg/file.js", "space here/node_modules/a\nfile.js"]) {
    assert.throws(() => assertDependencyIndexClean(`${path}\0`), /must not be tracked/);
  }
  assert.doesNotThrow(() => assertDependencyIndexClean(""));
  assert.doesNotThrow(() => assertDependencyIndexClean("apps/web/package.json\0docs/node_modules-guide.md\0"));
  assert.throws(() => assertDependencyIndexClean("unterminated"), /NUL-terminated/);
  assert.throws(() => assertDependencyIndexClean("\0"), /empty path/);
});

test("dependency index CLI consumes stdin and propagates validation failure", () => {
  const script = join(repoRoot, "scripts/release/check-dependency-index.mjs");
  const run = (input) => spawnSync(process.execPath, [script], {
    cwd: repoRoot, input, encoding: "utf8", timeout: 10_000, maxBuffer: 1024 * 1024,
  });
  const clean = run("apps/web/package.json\0");
  assert.equal(clean.error, undefined);
  assert.equal(clean.status, 0, clean.stderr);
  assert.match(clean.stdout, /dependency index is clean/);

  const rejected = run("apps/web/node_modules\0");
  assert.equal(rejected.error, undefined);
  assert.equal(rejected.signal, null);
  assert.notEqual(rejected.status, 0);
  assert.match(rejected.stderr, /generated node_modules paths must not be tracked/);
  assert.doesNotMatch(rejected.stdout, /dependency index is clean/);
});

test("index hygiene runs before installs on every dependency-policy and release-source path", () => {
  for (const block of [jobBlock(ci, "dependency-policy", "windows-arm-source-check"),
    jobBlock(releaseBuild, "verify-source", "build")]) {
    const check = block.indexOf("/usr/bin/git ls-files -z | node scripts/release/check-dependency-index.mjs");
    assert.ok(check >= 0, "fixed-path Git index check must run");
    assert.match(block.slice(0, check), /shell: bash\n        run: \|\n          set -euo pipefail\n          $/);
    const before = block.slice(0, check);
    const jobConditions = before.match(/^    if:.*$/gm) ?? [];
    assert.deepEqual(jobConditions, block.includes("  dependency-policy:")
      ? ["    if: inputs.validation_scope != 'windows-native-diagnostics'"] : []);
    assert.doesNotMatch(before, /^        if:/m);
    assert.ok(check < block.indexOf("Install verified"), "check precedes tool/dependency installation");
  }
});

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
  const escapedVersion = sourceVersion.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  assert.match(rehearsal, new RegExp(`default: v${escapedVersion}`));
  assert.match(
    npmCandidateAcceptance,
    new RegExp(`^      version:\\n[\\s\\S]*?^        default: ${escapedVersion}$`, 'm')
  );
  assert.match(versionParity, /json\("apps\/web\/package-lock\.json"\)/);
  assert.match(versionParity, /Hosted web lockfile root/);
  assert.match(versionParity, /README source badge/);
  assert.match(versionParity, /Roadmap release/);
  assert.match(versionParity, /phantom-release-version/);
  assert.match(versionParity, /Current changelog candidate/);
  assert.match(versionParity, /npm CLI README/);
  assert.match(versionParity, /npm MCP README/);
  assert.match(versionParity, /npm candidate acceptance default/);
  assert.equal(
    execFileSync(
      process.execPath,
      [join(repoRoot, "scripts/release/check-version-parity.mjs"), `v${sourceVersion}`],
      { cwd: repoRoot, encoding: "utf8" }
    ).trim(),
    `release version parity passed: ${sourceVersion} across 21 surfaces and 12 crates`
  );
});

test("installed wrappers bind release identity to their own package, independent of cwd and environment", () => {
  const home = mkdtempSync(join(tmpdir(), "phantom-wrapper-layout-"));
  try {
    const cwd = join(home, "unrelated-project");
    mkdirSync(cwd);
    writeFileSync(join(cwd, "package.json"), JSON.stringify({ version: "9.9.9" }));
    for (const directory of ["npm", "npm-mcp"]) {
      const installed = join(home, "consumer", "node_modules", directory);
      mkdirSync(join(installed, "bin"), { recursive: true });
      const wrapper = join(installed, "bin", "cli.js");
      writeFileSync(wrapper, readFileSync(join(repoRoot, directory, "bin", "cli.js")));
      writeFileSync(join(installed, "bin", "package-version.js"), readFileSync(join(repoRoot, directory, "bin", "package-version.js")));
      const metadata = join(installed, "package.json");
      const run = () => spawnSync(process.execPath, ["-e", `
        const wrapper = require(process.argv[1]);
        try { wrapper.getPlatformTarget({ platform: "unsupported", arch: "fixture" }); }
        catch (error) { process.stdout.write(error.message); }
      `, wrapper], {
        cwd, encoding: "utf8", timeout: 5_000, maxBuffer: 64 * 1024,
        env: { PATH: process.env.PATH, HOME: home, npm_package_version: "8.8.8", PHANTOM_VERSION: "7.7.7" },
      });
      writeFileSync(metadata, JSON.stringify({ version: "1.2.3-rc.1+build.7" }));
      const valid = run();
      assert.equal(valid.status, 0, valid.stderr);
      assert.match(valid.stdout, /releases\/tag\/v1\.2\.3-rc\.1\+build\.7/);
      assert.doesNotMatch(valid.stdout, /9\.9\.9|8\.8\.8|7\.7\.7/);
      for (const version of [null, 123, {}, "01.2.3", "1.2.3-01", "1.2.3\n", "../1.2.3", "1.2.3+bad space"]) {
        writeFileSync(metadata, JSON.stringify({ version }));
        const invalid = run();
        assert.notEqual(invalid.status, 0, `${directory} accepted ${JSON.stringify(version)}`);
        assert.match(invalid.stderr, /invalid packaged Phantom version/);
        assert.equal(invalid.stdout, "");
      }
    }
    assert.deepEqual(readdirSync(home).sort(), ["consumer", "unrelated-project"]);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("source parity refuses alternate wrapper version bindings and mismatched package metadata", () => {
  const root = mkdtempSync(join(tmpdir(), "phantom-version-binding-"));
  try {
    const carriers = [
      "scripts/release/check-version-parity.mjs", "Cargo.toml", "npm/package.json", "npm-mcp/package.json",
      "apps/web/package.json", "apps/web/package-lock.json", "CITATION.cff", "npm/README.md", "npm-mcp/README.md",
      "README.md", "ROADMAP.md", "CHANGELOG.md", "mcp-registry/server.json", "npm/bin/cli.js", "npm-mcp/bin/cli.js",
      "npm/bin/package-version.js", "npm-mcp/bin/package-version.js",
      "scripts/install.sh", "scripts/install.ps1", ".github/workflows/release-rehearsal.yml",
      ".github/workflows/npm-candidate-acceptance.yml", "apps/web/src/lib/public-release.ts",
      ...readdirSync(join(repoRoot, "crates"), { withFileTypes: true }).filter(p => p.isDirectory()).map(p => `crates/${p.name}/Cargo.toml`),
    ];
    for (const path of carriers) {
      mkdirSync(dirname(join(root, path)), { recursive: true });
      writeFileSync(join(root, path), readFileSync(join(repoRoot, path)));
    }
    const check = () => spawnSync(process.execPath, [join(root, "scripts/release/check-version-parity.mjs"), `v${sourceVersion}`], {
      cwd: root, encoding: "utf8", timeout: 5_000, maxBuffer: 64 * 1024,
    });
    assert.equal(check().status, 0);
    const entrypoint = join(root, "npm/bin/cli.js"), entrySource = readFileSync(entrypoint, "utf8");
    for (const alternate of ['require(process.env.PHANTOM_VERSION_MODULE)', 'require("./unexpected.js")']) {
      writeFileSync(entrypoint, entrySource.replace('require("./package-version.js")', alternate));
      const invalid = check();
      assert.notEqual(invalid.status, 0);
      assert.match(invalid.stderr, /must bind VERSION to its own packaged package\.json/);
    }
    writeFileSync(entrypoint, entrySource);
    const wrapper = join(root, "npm/bin/package-version.js"), source = readFileSync(wrapper, "utf8");
    for (const alternate of [`"${sourceVersion}"`, "process.env.npm_package_version", 'require(process.cwd() + "/package.json").version']) {
      writeFileSync(wrapper, source.replace('require("../package.json").version', alternate));
      const invalid = check();
      assert.notEqual(invalid.status, 0);
      assert.match(invalid.stderr, /must bind VERSION to its own packaged package\.json/);
    }
    writeFileSync(wrapper, source);
    const metadata = join(root, "npm/package.json");
    const packageJson = JSON.parse(readFileSync(metadata, "utf8")); packageJson.version = "9.9.9";
    writeFileSync(metadata, JSON.stringify(packageJson));
    const mismatch = check();
    assert.notEqual(mismatch.status, 0);
    assert.match(mismatch.stderr, /release version mismatch/);
  } finally { rmSync(root, { recursive: true, force: true }); }
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
  assert.match(publish, /needs: \[qualify, verify-attestations\]/);
  assert.match(publish, /environment:\n      name: release/);
  assert.match(publish, /contents: write/);
  assert.match(release, /^  build-and-verify:\n(?:.|\n)*?uses: \.\/\.github\/workflows\/release-build\.yml/m);
  assert.match(release, /release_tag: \$\{\{ github\.ref_name \}\}/);
  assert.match(attest, /needs: \[qualify, build-and-verify\]/);
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

  for (const [readme, packageJson, packageName] of [
    [npmReadme, npmPackage, "phantom-secrets"],
    [npmMcpReadme, npmMcpPackage, "phantom-secrets-mcp"],
  ]) {
    const escapedVersion = packageJson.version.replaceAll(".", "\\.");
    assert.match(readme, new RegExp("This wrapper is version `" + escapedVersion + "`"));
    assert.match(readme, new RegExp(`npm view ${packageName}@${escapedVersion}`));
    assert.match(readme, new RegExp(`releases/tag/v${escapedVersion}`));
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
  assert.equal(npmPackage.version, sourceVersion, "CLI wrapper follows Cargo source version");
  assert.equal(npmMcpPackage.version, sourceVersion, "MCP wrapper follows Cargo source version");
  assertCandidateExamples(readiness, sourceVersion);

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
  assert.match(npmStage, /packs\[0\]\.entryCount !== expectedFiles\.length/);
  assert.match(npmStage, /expectedPackFiles\(version\)/);
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

test("current npm package contents are exactly the six reviewed files", () => {
  const expectedFiles = ["LICENSE", "README.md", "bin/cli.js", "bin/package-version.js", "install.js", "package.json"];

  for (const [directory, packageName] of [
    ["npm", "phantom-secrets"],
    ["npm-mcp", "phantom-secrets-mcp"],
  ]) {
    const pack = inspectPack(directory);
    assert.equal(pack.name, packageName);
    assert.equal(pack.version, sourceVersion);
    assert.equal(pack.entryCount, 6);
    assert.deepEqual(
      pack.files.map(({ path }) => path).sort(),
      expectedFiles
    );
  }
});

test("PowerShell candidate pin follows source metadata while public reference stays fixed", () => {
  const installer = readFileSync(join(repoRoot, "scripts/install.ps1"), "utf8");
  assertPowershellCandidate(installer, npmPackage.version, npmMcpPackage.version);
  const pin = `$CandidateTag = 'v${npmPackage.version}'`;
  for (const mutant of [installer.replace(pin, "$CandidateTag = 'v0.7.10'"),
    installer.replace(pin, ""), `${installer}\n${pin}\n`,
    `${installer}\n$candidatetag = 'v99.98.97'\n`]) {
    assert.throws(() => assertPowershellCandidate(mutant, npmPackage.version, npmMcpPackage.version), /one exact source-version assignment/);
  }
  for (const invalid of [undefined, 8, "", "01.2.3", "0.8.2'", "0.8.2\n"]) {
    assert.throws(() => assertPowershellCandidate(installer, invalid, invalid), /candidate source version/);
  }
  assert.throws(() => assertPowershellCandidate(installer, npmPackage.version, "99.98.97"), /source versions must agree/);
  assertPowershellCandidate("$CandidateTag = 'v99.98.97'\r\n", "99.98.97", "99.98.97");

  const start = ci.indexOf("      - name: Parse candidate and public-reference PowerShell installers");
  const end = ci.indexOf("      - name: Exercise the Windows installer", start);
  assert.ok(start >= 0 && end > start);
  const block = ci.slice(start, end);
  assert.ok(block.includes("node scripts/release/check-powershell-candidate.mjs"));
  assert.ok(block.includes("[void][scriptblock]::Create((Get-Content -LiteralPath scripts/install.ps1 -Raw))"));
  assert.ok(block.includes("[void][scriptblock]::Create((Get-Content -LiteralPath apps/web/public/install.ps1 -Raw))"));
  assert.ok(block.includes("$PSNativeCommandUseErrorActionPreference = $true"));
  const publicVersion = "0.8.7";
  const publicInstaller = readFileSync(join(repoRoot, "apps/web/public/install.ps1"), "utf8");
  assertPowershellCandidate(publicInstaller, publicVersion, publicVersion);
  assert.ok(block.includes(`Select-String -LiteralPath apps/web/public/install.ps1 -Pattern '\\$CandidateTag = ''v${publicVersion}''' -Quiet`));
  assert.doesNotMatch(block, /v0\.7\.10/);
  execFileSync(process.execPath, [join(repoRoot, "scripts/release/check-powershell-candidate.mjs")], { cwd: repoRoot });
});

test("Unix candidate pin rejects stale, missing, duplicate and malformed source bindings", () => {
  const installer = readFileSync(join(repoRoot, "scripts/install.sh"), "utf8");
  const pin = `CANDIDATE_TAG="v${sourceVersion}"`;
  assertShellCandidate(installer, npmPackage.version, npmMcpPackage.version);
  for (const mutant of [installer.replace(pin, 'CANDIDATE_TAG="v0.7.10"'),
    installer.replace(pin, ""), `${installer}\n${pin}\n`,
    installer.replace(pin, ` ${pin}`), installer.replace(pin, `${pin} # trailing`),
    `${installer}\nexport CANDIDATE_TAG="v99.98.97"\n`, `${installer}\nreadonly CANDIDATE_TAG="v99.98.97"\n`]) {
    assert.throws(() => assertShellCandidate(mutant, npmPackage.version, npmMcpPackage.version), /one exact source-version assignment/);
  }
  for (const invalid of [undefined, 8, "", "01.2.3", "0.8.2'", "0.8.2\n"]) {
    assert.throws(() => assertShellCandidate(installer, invalid, invalid), /candidate source version/);
  }
  assert.throws(() => assertShellCandidate(installer, sourceVersion, "99.98.97"), /source versions must agree/);
  assertShellCandidate('CANDIDATE_TAG="v99.98.97"\r\n', "99.98.97", "99.98.97");
});
