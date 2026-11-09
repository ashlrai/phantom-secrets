#!/usr/bin/env node

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadSources } from "../freshness/sources.mjs";

function assertCandidateVersions(cliVersion, mcpVersion) {
  assert.equal(typeof cliVersion, "string", "candidate source version must be a string");
  assert.equal(cliVersion.trim(), cliVersion, "candidate source version must not contain surrounding whitespace");
  assert.match(cliVersion, /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/,
    "candidate source version must be stable SemVer");
  assert.equal(mcpVersion, cliVersion, "CLI and MCP source versions must agree");
}

export function assertShellCandidate(installer, cliVersion, mcpVersion) {
  assertCandidateVersions(cliVersion, mcpVersion);
  const assignments = installer.split(/\r?\n/).filter((line) => /^\s*(?:(?:export|readonly)\s+)?CANDIDATE_TAG\s*=/.test(line));
  assert.deepEqual(assignments, [`CANDIDATE_TAG="v${cliVersion}"`],
    "candidate Unix installer must have one exact source-version assignment");
}

export function assertPowershellCandidate(installer, cliVersion, mcpVersion, label = "candidate") {
  assertCandidateVersions(cliVersion, mcpVersion);
  const assignments = installer.split(/\r?\n/).filter((line) => /^\s*\$CandidateTag\s*=/i.test(line));
  assert.deepEqual(assignments, [`$CandidateTag = 'v${cliVersion}'`],
    `${label} PowerShell installer must have one exact source-version assignment`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
  const read = (path) => readFileSync(join(repoRoot, path), "utf8");
  const cliVersion = JSON.parse(read("npm/package.json")).version;
  const mcpVersion = JSON.parse(read("npm-mcp/package.json")).version;
  assertPowershellCandidate(read("scripts/install.ps1"), cliVersion, mcpVersion);
  // The public copy must stay pinned to the evidenced release recorded in
  // apps/web/src/lib/public-release.ts, not the candidate. Checking it here —
  // in repo code instead of an inline workflow literal — keeps the gate from
  // drifting stale between release bumps (nightly run 42492932624).
  const publicVersion = loadSources(repoRoot).publicRelease.version;
  assertPowershellCandidate(read("apps/web/public/install.ps1"), publicVersion, publicVersion, "public-reference");
  console.log(`PowerShell pins passed: candidate v${cliVersion}, public v${publicVersion}`);
}
