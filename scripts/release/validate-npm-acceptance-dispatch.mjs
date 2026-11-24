#!/usr/bin/env node

import { appendFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPOSITORY = "ashlrai/phantom-secrets";
const COMPONENT = "(0|[1-9][0-9]{0,63})";
const STABLE = new RegExp(`^${COMPONENT}\\.${COMPONENT}\\.${COMPONENT}$`);
const RELEASE_TAG = new RegExp(`^v${COMPONENT}\\.${COMPONENT}\\.${COMPONENT}$`);
const TAG_REF = new RegExp(`^refs/tags/v${COMPONENT}\\.${COMPONENT}\\.${COMPONENT}$`);
const SHA = /^[0-9a-f]{40}$/;
const INTEGRITY = /^sha512-([A-Za-z0-9+/]{86}==)$/;

function fail(message) {
  throw new Error(message);
}

function canonicalVersion(value, label) {
  if (typeof value !== "string") fail(`${label} failed format check`);
  const match = STABLE.exec(value);
  if (!match) fail(`${label} failed format check`);
  return `${match[1]}.${match[2]}.${match[3]}`;
}

function canonicalMode(value) {
  if (value === "prepublication") return "prepublication";
  if (value === "published-candidate") return "published-candidate";
  fail("mode failed format check");
}

function canonicalSha(value) {
  if (typeof value !== "string") fail("release_source_sha failed format check");
  const match = SHA.exec(value);
  if (!match) fail("release_source_sha failed format check");
  return match[0];
}

function canonicalIntegrity(value, label) {
  if (typeof value !== "string") fail(`${label} failed format check`);
  if (value === "") return "";
  const match = INTEGRITY.exec(value);
  if (!match) fail(`${label} failed format check`);
  const digest = Buffer.from(match[1], "base64");
  const encoded = digest.toString("base64");
  if (digest.length !== 64 || encoded !== match[1]) fail(`${label} failed format check`);
  return `sha512-${encoded}`;
}

function canonicalDefaultBranch(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9._/-]{1,255}$/.test(value)) {
    fail("default branch failed format check");
  }
  if (
    value.includes("..") ||
    value.includes("//") ||
    value.startsWith("/") ||
    value.endsWith("/") ||
    value.startsWith(".") ||
    value.endsWith(".")
  ) {
    fail("default branch failed format check");
  }
  return value;
}

function assertProtectedRef(ref, defaultBranch, version) {
  const branch = canonicalDefaultBranch(defaultBranch);
  if (typeof ref !== "string") fail("ref is not the default branch or a release tag");
  if (ref === `refs/heads/${branch}`) return;
  const tag = TAG_REF.exec(ref);
  if (!tag) fail("ref is not the default branch or a release tag");
  const tagVersion = `${tag[1]}.${tag[2]}.${tag[3]}`;
  if (tagVersion !== version) fail("version does not match the release tag");
}

export function validateNpmAcceptanceDispatch(input) {
  if (input.repository !== REPOSITORY) {
    fail("npm acceptance is restricted to ashlrai/phantom-secrets");
  }
  const mode = canonicalMode(input.mode);
  const version = canonicalVersion(input.version, "version");
  const previousLatest = canonicalVersion(input.previousLatest, "previous_latest");
  const previousCandidate = canonicalVersion(input.previousCandidate, "previous_candidate");
  if (previousLatest === version) fail("previous_latest must differ from the candidate version");
  if (previousCandidate === version) fail("previous_candidate must differ from the candidate version");
  const releaseSourceSha = canonicalSha(input.releaseSourceSha);
  const primaryIntegrity = canonicalIntegrity(input.primaryIntegrity, "primary_integrity");
  const mcpIntegrity = canonicalIntegrity(input.mcpIntegrity, "mcp_integrity");
  if (mode === "prepublication") {
    if (primaryIntegrity !== "" || mcpIntegrity !== "") {
      fail("prepublication mode rejects public integrity inputs");
    }
  } else if (primaryIntegrity === "" || mcpIntegrity === "") {
    fail("published-candidate mode requires both approved sha512 integrity values");
  }
  assertProtectedRef(input.ref, input.defaultBranch, version);
  const releaseTag = `v${version}`;
  if (!RELEASE_TAG.test(releaseTag)) fail("release_tag failed format check");
  return {
    mode,
    version,
    releaseSourceSha,
    primaryIntegrity,
    mcpIntegrity,
    previousLatest,
    previousCandidate,
    releaseTag,
  };
}

export function formatGithubOutput(values) {
  const rows = [
    ["mode", values.mode],
    ["version", values.version],
    ["release_source_sha", values.releaseSourceSha],
    ["primary_integrity", values.primaryIntegrity],
    ["mcp_integrity", values.mcpIntegrity],
    ["previous_latest", values.previousLatest],
    ["previous_candidate", values.previousCandidate],
    ["release_tag", values.releaseTag],
  ];
  const lines = rows.map(([key, value]) => {
    if (!/^[a-z_]+$/.test(key) || typeof value !== "string" || /[\r\n\0]/.test(value)) {
      throw new Error("refusing to emit an unchecked output");
    }
    return `${key}=${value}`;
  });
  return `${lines.join("\n")}\n`;
}

function fromEnv(env) {
  return validateNpmAcceptanceDispatch({
    repository: env.GITHUB_REPOSITORY,
    ref: env.ACCEPTANCE_REF,
    defaultBranch: env.ACCEPTANCE_DEFAULT_BRANCH,
    mode: env.RAW_MODE,
    version: env.RAW_VERSION,
    releaseSourceSha: env.RAW_RELEASE_SOURCE_SHA,
    primaryIntegrity: env.RAW_PRIMARY_INTEGRITY ?? "",
    mcpIntegrity: env.RAW_MCP_INTEGRITY ?? "",
    previousLatest: env.RAW_PREVIOUS_LATEST,
    previousCandidate: env.RAW_PREVIOUS_CANDIDATE,
  });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const output = process.env.GITHUB_OUTPUT;
    if (!output) fail("GITHUB_OUTPUT is unset");
    appendFileSync(output, formatGithubOutput(fromEnv(process.env)));
  } catch (error) {
    console.error(error instanceof Error ? error.message : "acceptance input validation failed");
    process.exit(1);
  }
}
