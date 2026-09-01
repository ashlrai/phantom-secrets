#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const stableTagPattern = /^v\d+\.\d+\.\d+$/;
const shaPattern = /^[0-9a-f]{40}$/i;

function runGit(args) {
  try {
    return execFileSync("git", args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 30_000,
      maxBuffer: 1024 * 1024,
    });
  } catch (error) {
    const stderr = typeof error.stderr === "string" ? error.stderr.trim() : "";
    throw new Error(`could not verify release tag binding${stderr ? `: ${stderr}` : ""}`);
  }
}

export function verifyTagBinding(
  tag,
  expectedCommit,
  remote = "origin",
  protectedBranch = "refs/heads/main",
) {
  if (!stableTagPattern.test(tag ?? "") || !shaPattern.test(expectedCommit ?? "")) {
    throw new Error(
      "usage: verify-github-tag-binding.mjs vMAJOR.MINOR.PATCH EXPECTED_COMMIT [REMOTE] [PROTECTED_BRANCH]",
    );
  }
  if (!remote || remote.startsWith("-") || /[\r\n\0]/.test(remote)) {
    throw new Error("release tag remote is invalid");
  }
  if (
    !/^refs\/heads\/[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(protectedBranch ?? "") ||
    protectedBranch.includes("..") ||
    protectedBranch.includes("//") ||
    protectedBranch.includes("@{") ||
    protectedBranch.endsWith("/") ||
    protectedBranch.endsWith(".")
  ) {
    throw new Error("protected release branch ref is invalid");
  }

  const tagRef = `refs/tags/${tag}`;
  const peeledRef = `${tagRef}^{}`;
  const output = runGit(["ls-remote", remote, tagRef, peeledRef, protectedBranch]);
  const refs = new Map();
  for (const line of output.trim() === "" ? [] : output.trim().split(/\r?\n/)) {
    const match = line.match(/^([0-9a-f]{40})\t(.+)$/i);
    if (
      !match ||
      ![tagRef, peeledRef, protectedBranch].includes(match[2]) ||
      refs.has(match[2])
    ) {
      throw new Error("remote release tag response is malformed or ambiguous");
    }
    refs.set(match[2], match[1].toLowerCase());
  }

  const tagObject = refs.get(tagRef);
  const peeledCommit = refs.get(peeledRef);
  if (!tagObject || !peeledCommit) {
    throw new Error(`remote release tag ${tag} must exist and be annotated`);
  }
  if (tagObject === peeledCommit) {
    throw new Error(`remote release tag ${tag} is not an annotated tag object`);
  }
  if (peeledCommit !== expectedCommit.toLowerCase()) {
    throw new Error(
      `remote release tag ${tag} resolves to ${peeledCommit}, expected ${expectedCommit.toLowerCase()}`,
    );
  }
  const branchCommit = refs.get(protectedBranch);
  if (!branchCommit) {
    throw new Error(`protected release branch ${protectedBranch} does not exist remotely`);
  }
  if (branchCommit !== expectedCommit.toLowerCase()) {
    throw new Error(
      `protected release branch ${protectedBranch} is at ${branchCommit}, expected ${expectedCommit.toLowerCase()}`,
    );
  }

  runGit(["cat-file", "-e", `${expectedCommit}^{commit}`]);
  return { tagObject, peeledCommit, protectedBranch, branchCommit };
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  if (process.argv.length < 4 || process.argv.length > 6) {
    throw new Error(
      "usage: verify-github-tag-binding.mjs vMAJOR.MINOR.PATCH EXPECTED_COMMIT [REMOTE] [PROTECTED_BRANCH]",
    );
  }
  const result = verifyTagBinding(
    process.argv[2],
    process.argv[3],
    process.argv[4],
    process.argv[5],
  );
  console.log(
    `verified annotated remote tag ${process.argv[2]} and ${result.protectedBranch} at commit ${result.peeledCommit}`,
  );
}
