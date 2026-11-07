#!/usr/bin/env node

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

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

export function assertPowershellCandidate(installer, cliVersion, mcpVersion) {
  assertCandidateVersions(cliVersion, mcpVersion);
  const assignments = installer.split(/\r?\n/).filter((line) => /^\s*\$CandidateTag\s*=/i.test(line));
  assert.deepEqual(assignments, [`$CandidateTag = 'v${cliVersion}'`],
    "candidate PowerShell installer must have one exact source-version assignment");
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const read = (path) => readFileSync(new URL(`../../${path}`, import.meta.url), "utf8");
  assertPowershellCandidate(read("scripts/install.ps1"),
    JSON.parse(read("npm/package.json")).version,
    JSON.parse(read("npm-mcp/package.json")).version);
  console.log("candidate PowerShell source-version pin passed");
}
