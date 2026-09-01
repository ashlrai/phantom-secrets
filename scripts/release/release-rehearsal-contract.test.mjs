#!/usr/bin/env node

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const release = readFileSync(join(repoRoot, ".github/workflows/release.yml"), "utf8");
const rehearsal = readFileSync(
  join(repoRoot, ".github/workflows/release-rehearsal.yml"),
  "utf8"
);

const tagOnlyCondition =
  "if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')";

function jobBlock(source, name, nextName) {
  const start = source.indexOf(`\n  ${name}:\n`);
  assert.notEqual(start, -1, `missing ${name} job`);
  const end = nextName ? source.indexOf(`\n  ${nextName}:\n`, start + 1) : source.length;
  assert.notEqual(end, -1, `missing ${nextName} job after ${name}`);
  return source.slice(start, end);
}

test("manual rehearsal delegates to the shared graph with read-only authority", () => {
  assert.match(rehearsal, /^on:\n  workflow_dispatch:/m);
  assert.match(rehearsal, /^permissions:\n  contents: read$/m);
  assert.match(rehearsal, /uses: \.\/\.github\/workflows\/release\.yml/);
  assert.match(rehearsal, /release_tag: \$\{\{ inputs\.release_tag \}\}/);
  assert.doesNotMatch(rehearsal, /(?:contents|attestations|id-token): write/);
  assert.doesNotMatch(rehearsal, /environment:/);
  assert.doesNotMatch(rehearsal, /(?:npm|cargo|mcp-publisher) publish|gh release/);
});

test("shared graph validates the exact tag before building and keeps native acceptance exact", () => {
  assert.match(release, /^  workflow_call:\n    inputs:\n      release_tag:/m);
  assert.match(
    release,
    /PHANTOM_RELEASE_TAG: \$\{\{ inputs\.release_tag \|\| github\.ref_name \}\}/
  );

  const parity = release.indexOf(
    'node scripts/release/check-version-parity.mjs "$PHANTOM_RELEASE_TAG"'
  );
  const buildJob = release.indexOf("\n  build:\n");
  assert.ok(parity > 0 && parity < buildJob, "version/tag validation must precede builds");

  const native = jobBlock(release, "native-acceptance", "verify-artifacts");
  assert.match(native, /needs: build/);
  assert.match(native, /run: node scripts\/release\/native-release-smoke\.mjs/);
  assert.match(native, /run: node scripts\/release\/native-installer-acceptance\.mjs/);
  assert.match(native, /Install the exact archive and prove transaction rollback/);
  assert.doesNotMatch(native, /(?:npm|cargo|mcp-publisher) publish|gh release/);
});

test("rehearsal reaches checksum and SBOM verification without publication authority", () => {
  const verify = jobBlock(release, "verify-artifacts", "attest");
  assert.match(verify, /needs: \[build, native-acceptance\]/);
  assert.match(verify, /^    permissions:\n      contents: read$/m);
  assert.match(verify, /Generate SHA-256 checksums/);
  assert.match(verify, /node scripts\/release\/verify-release-artifacts\.mjs artifacts/);
  assert.match(verify, /name: verified-release-bundle/);
  assert.doesNotMatch(verify, /(?:contents|attestations|id-token): write/);
  assert.doesNotMatch(verify, /environment:/);
});

test("attestation and immutable release remain tag-push-only", () => {
  const attest = jobBlock(release, "attest", "release");
  const publish = jobBlock(release, "release");
  assert.match(attest, new RegExp(tagOnlyCondition.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.match(publish, new RegExp(tagOnlyCondition.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.match(attest, /attestations: write/);
  assert.match(attest, /id-token: write/);
  assert.match(publish, /environment:\n      name: release/);
  assert.match(publish, /contents: write/);
});

test("tag binding remains mandatory for tag pushes and absent from rehearsal caller", () => {
  const binding = release.indexOf("- name: Verify immutable annotated release tag binding");
  assert.ok(binding > 0, "missing tag-binding step");
  const following = release.slice(binding, binding + 500);
  assert.match(following, new RegExp(tagOnlyCondition.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.match(following, /verify-github-tag-binding\.mjs/);
  assert.doesNotMatch(rehearsal, /verify-github-tag-binding|refs\/tags/);
});
