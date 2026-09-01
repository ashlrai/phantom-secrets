#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const fingerprintPattern =
  /^([0-9a-f]{40}):([^:\r\n]+):([a-z0-9][a-z0-9_-]*):([1-9][0-9]*)$/;

export function validateGitleaksIgnore(contents, isApprovedCommit) {
  const fingerprints = contents
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line !== "" && !line.startsWith("#"));

  if (new Set(fingerprints).size !== fingerprints.length) {
    throw new Error("Gitleaks ignore fingerprints must be unique");
  }
  const sorted = [...fingerprints].sort();
  if (fingerprints.some((fingerprint, index) => fingerprint !== sorted[index])) {
    throw new Error("Gitleaks ignore fingerprints must be sorted");
  }

  for (const fingerprint of fingerprints) {
    const match = fingerprint.match(fingerprintPattern);
    if (!match) {
      throw new Error(`Malformed Gitleaks fingerprint: ${fingerprint}`);
    }
    if (!isApprovedCommit(match[1])) {
      throw new Error(
        `Gitleaks fingerprint commit is not reachable from the candidate or canonical origin heads: ${match[1]}`,
      );
    }
  }
  return fingerprints.length;
}

function gitIsAncestor(commit, candidate) {
  try {
    execFileSync("git", ["merge-base", "--is-ancestor", commit, candidate], {
      stdio: "ignore",
      timeout: 30_000,
    });
    return true;
  } catch {
    return false;
  }
}

function gitOriginHeads() {
  const refs = execFileSync(
    "git",
    ["for-each-ref", "--format=%(refname)", "refs/remotes/origin/"],
    { encoding: "utf8", timeout: 30_000 },
  )
    .split(/\r?\n/)
    .map((ref) => ref.trim())
    .filter((ref) => ref !== "" && ref !== "refs/remotes/origin/HEAD")
    .sort();

  if (refs.length === 0) {
    throw new Error(
      "No canonical origin heads found; fetch +refs/heads/*:refs/remotes/origin/* before validation",
    );
  }
  return refs;
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  if (process.argv.length > 4) {
    throw new Error("usage: validate-gitleaks-ignore.mjs [ignore-path] [candidate]");
  }
  const ignorePath = process.argv[2] ?? ".gitleaksignore";
  const candidate = process.argv[3] ?? "HEAD";
  execFileSync("git", ["rev-parse", "--verify", `${candidate}^{commit}`], {
    stdio: "ignore",
    timeout: 30_000,
  });
  const approvedRefs = [candidate, ...gitOriginHeads()];
  const count = validateGitleaksIgnore(
    readFileSync(ignorePath, "utf8"),
    (commit) => approvedRefs.some((ref) => gitIsAncestor(commit, ref)),
  );
  console.log(
    `Gitleaks ignore policy verified: ${count} exact fingerprints reachable from ${candidate} or ${approvedRefs.length - 1} canonical origin heads`,
  );
}
