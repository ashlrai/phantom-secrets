#!/usr/bin/env node

import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const semverSource =
  "(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)" +
  "(?:-((?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(?:\\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?" +
  "(?:\\+([0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*))?";
const semverPattern = new RegExp(`^${semverSource}$`);
const tagPattern = new RegExp(`^v${semverSource}$`);

function read(relativePath) {
  return readFileSync(join(repoRoot, relativePath), "utf8");
}

function json(relativePath) {
  return JSON.parse(read(relativePath));
}

function requireMatch(value, pattern, label) {
  const match = value.match(pattern);
  if (!match) {
    throw new Error(`could not read ${label}`);
  }
  return match[1];
}

const cargoToml = read("Cargo.toml");
const workspaceVersion = requireMatch(
  cargoToml,
  /\[workspace\.package\][\s\S]*?^version\s*=\s*"([^"]+)"/m,
  "Cargo workspace version"
);
if (!semverPattern.test(workspaceVersion)) {
  throw new Error(`Cargo workspace version is not valid SemVer: ${workspaceVersion}`);
}
const npmCliVersion = json("npm/package.json").version;
const npmMcpVersion = json("npm-mcp/package.json").version;
const webVersion = json("apps/web/package.json").version;
const webLock = json("apps/web/package-lock.json");
const webLockVersion = webLock.version;
const webLockRootVersion = webLock.packages?.[""]?.version;
const citationVersion = requireMatch(
  read("CITATION.cff"),
  /^version:\s*([^\s]+)$/m,
  "citation metadata version"
);
const readme = read("README.md");
const readmeSourceVersion = requireMatch(
  readme,
  /source_version-v([0-9]+\.[0-9]+\.[0-9]+)-/,
  "README source badge version"
);
const roadmapReleaseVersion = requireMatch(
  read("ROADMAP.md"),
  /<!-- phantom-release-version: ([0-9]+\.[0-9]+\.[0-9]+) -->/,
  "roadmap release version"
);
const changelogCandidateVersion = requireMatch(
  read("CHANGELOG.md"),
  /^## \[([0-9]+\.[0-9]+\.[0-9]+)\] - /m,
  "current changelog candidate version"
);
const registry = json("mcp-registry/server.json");
const registryPackage = registry.packages.find(
  (entry) => entry.identifier === "phantom-secrets-mcp"
);
if (!registryPackage) {
  throw new Error("MCP registry package phantom-secrets-mcp is missing");
}

const wrapperVersion = requireMatch(
  read("npm-mcp/bin/cli.js"),
  /^const VERSION\s*=\s*"([^"]+)";/m,
  "npm MCP wrapper version"
);
const cliWrapperVersion = requireMatch(
  read("npm/bin/cli.js"),
  /^const VERSION\s*=\s*"([^"]+)";/m,
  "npm CLI wrapper version"
);
const shellInstallerVersion = requireMatch(
  read("scripts/install.sh"),
  /^CANDIDATE_TAG="v([^"]+)"$/m,
  "Unix installer candidate tag"
);
const powershellInstallerVersion = requireMatch(
  read("scripts/install.ps1"),
  /^\$CandidateTag\s*=\s*'v([^']+)'$/m,
  "PowerShell installer candidate tag"
);
const rehearsalDefaultVersion = requireMatch(
  read(".github/workflows/release-rehearsal.yml"),
  /^        default:\s*v([^\s]+)$/m,
  "release rehearsal default tag"
);
const npmAcceptanceDefaultVersion = requireMatch(
  read(".github/workflows/npm-candidate-acceptance.yml"),
  /^      version:\n[\s\S]*?^        default:\s*([^\s]+)$/m,
  "npm candidate acceptance default version"
);
const versions = new Map([
  ["Cargo workspace", workspaceVersion],
  ["npm CLI package", npmCliVersion],
  ["npm MCP package", npmMcpVersion],
  ["Hosted web application", webVersion],
  ["Hosted web lockfile", webLockVersion],
  ["Hosted web lockfile root", webLockRootVersion],
  ["Citation metadata", citationVersion],
  ["README source badge", readmeSourceVersion],
  ["Roadmap release", roadmapReleaseVersion],
  ["Current changelog candidate", changelogCandidateVersion],
  ["npm CLI wrapper", cliWrapperVersion],
  ["npm MCP wrapper", wrapperVersion],
  ["Unix direct installer", shellInstallerVersion],
  ["PowerShell direct installer", powershellInstallerVersion],
  ["Release rehearsal default", rehearsalDefaultVersion],
  ["npm candidate acceptance default", npmAcceptanceDefaultVersion],
  ["MCP registry server", registry.version],
  ["MCP registry npm package", registryPackage.version],
]);

const expectedTag = process.argv[2];
if (process.argv.length > 3 || (expectedTag && !tagPattern.test(expectedTag))) {
  throw new Error("usage: check-version-parity.mjs [v<semver>]");
}
if (expectedTag) {
  versions.set("release tag", expectedTag.slice(1));
}

const changelogAnchor = workspaceVersion.replaceAll(".", "");
if (!readme.includes(`](CHANGELOG.md#${changelogAnchor}---`)) {
  throw new Error(
    `README source badge does not link to the ${workspaceVersion} changelog entry`
  );
}

const mismatches = [...versions].filter(([, version]) => version !== workspaceVersion);
if (mismatches.length > 0) {
  const details = [...versions]
    .map(([label, version]) => `${label}: ${version}`)
    .join("\n");
  throw new Error(`release version mismatch\n${details}`);
}

const crateDirs = readdirSync(join(repoRoot, "crates"), { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name)
  .sort();
for (const crateDir of crateDirs) {
  const manifest = read(`crates/${crateDir}/Cargo.toml`);
  if (!/^version\.workspace\s*=\s*true\s*$/m.test(manifest)) {
    throw new Error(`${crateDir} does not inherit the workspace version`);
  }
}

console.log(
  `release version parity passed: ${workspaceVersion} across ${versions.size} surfaces and ${crateDirs.length} crates`
);
