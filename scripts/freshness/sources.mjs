#!/usr/bin/env node

// Source-of-truth readers for the freshness generator. Every marked
// `fresh:` block is rendered from these values only. When the sources
// disagree the repository's own release metadata is inconsistent, so
// loading fails closed instead of picking a winner.

import { readFileSync } from "node:fs";
import { join } from "node:path";

const SEMVER =
  /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

function read(root, rel) {
  return readFileSync(join(root, rel), "utf8");
}

function readPackage(root, rel) {
  const parsed = JSON.parse(read(root, rel));
  if (typeof parsed.name !== "string" || parsed.name === "") {
    throw new Error(`${rel} has no package name`);
  }
  if (typeof parsed.version !== "string" || !SEMVER.test(parsed.version)) {
    throw new Error(`${rel} version is missing or not semver`);
  }
  return { name: parsed.name, version: parsed.version };
}

// GitHub renders `## [0.7.9] - 2026-09-06` under the `#079---2026-09-06`
// anchor: lowercase, drop characters outside [a-z0-9 -], fold spaces to
// hyphens.
export function githubAnchor(headingText) {
  return headingText
    .toLowerCase()
    .replace(/[^a-z0-9 -]/g, "")
    .replace(/ /g, "-");
}

export function loadSources(root) {
  const cargoToml = read(root, "Cargo.toml");
  const versionMatch = cargoToml.match(
    /\[workspace\.package\][\s\S]*?^version\s*=\s*"([^"]+)"/m,
  );
  if (!versionMatch) {
    throw new Error("Cargo.toml has no [workspace.package] version");
  }
  const version = versionMatch[1];
  if (!SEMVER.test(version)) {
    throw new Error(`Cargo workspace version is not semver: ${version}`);
  }

  const npmCli = readPackage(root, "npm/package.json");
  const npmMcp = readPackage(root, "npm-mcp/package.json");

  const changelog = read(root, "CHANGELOG.md");
  const releaseMatch = changelog.match(
    /^## \[(\d+\.\d+\.\d+)\] - (\d{4}-\d{2}-\d{2})/m,
  );
  if (!releaseMatch) {
    throw new Error("CHANGELOG.md has no candidate `## [x.y.z] - date` section");
  }
  const [, releaseVersion, releaseDate] = releaseMatch;

  const mismatches = [
    ["npm/package.json", npmCli.version],
    ["npm-mcp/package.json", npmMcp.version],
    ["CHANGELOG.md latest candidate", releaseVersion],
  ].filter(([, seen]) => seen !== version);
  if (mismatches.length > 0) {
    const detail = mismatches
      .map(([label, seen]) => `${label} is ${seen}`)
      .join("; ");
    throw new Error(
      `freshness sources disagree: Cargo workspace version is ${version}; ${detail}`,
    );
  }

  // Published evidence is an explicit, separately reviewed receipt. Never infer
  // publication from a source-version bump or a dated candidate changelog.
  const published = JSON.parse(read(root, "scripts/freshness/published-release.json"));
  if (typeof published.version !== "string" || !SEMVER.test(published.version)) {
    throw new Error("published release version is missing or not semver");
  }
  if (published.url !== `https://github.com/ashlrai/phantom-secrets/releases/tag/v${published.version}`) {
    throw new Error("published release URL must match its exact canonical tag");
  }

  return {
    published: { ...published, tag: `v${published.version}` },
    version,
    tag: `v${version}`,
    npmCli,
    npmMcp,
    release: {
      version: releaseVersion,
      date: releaseDate,
      anchor: githubAnchor(`[${releaseVersion}] - ${releaseDate}`),
    },
  };
}
