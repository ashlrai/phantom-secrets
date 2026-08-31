#!/usr/bin/env node

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { lstatSync, readFileSync, readdirSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const EXPECTED_ARCHIVES = Object.freeze([
  "phantom-aarch64-apple-darwin.tar.gz",
  "phantom-x86_64-apple-darwin.tar.gz",
  "phantom-aarch64-unknown-linux-gnu.tar.gz",
  "phantom-x86_64-unknown-linux-gnu.tar.gz",
  "phantom-aarch64-pc-windows-msvc.zip",
  "phantom-x86_64-pc-windows-msvc.zip",
]);
const MAX_ARCHIVE_BYTES = 100 * 1024 * 1024;
const MAX_SBOM_BYTES = 16 * 1024 * 1024;

function walkFiles(root, current = root) {
  const files = [];
  for (const entry of readdirSync(current, { withFileTypes: true })) {
    const path = join(current, entry.name);
    const stat = lstatSync(path);
    if (stat.isSymbolicLink()) throw new Error(`release artifact must not be a symlink: ${path}`);
    if (stat.isDirectory()) files.push(...walkFiles(root, path));
    else if (stat.isFile()) files.push(path);
    else throw new Error(`release artifact must be a regular file: ${path}`);
  }
  return files;
}

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function parseChecksumFile(path, expectedName) {
  const text = readFileSync(path, "utf8");
  const match = text.match(/^([0-9a-f]{64})  ([^\r\n\s]+)\r?\n?$/i);
  if (!match || match[2] !== expectedName) {
    throw new Error(`malformed checksum sidecar for ${expectedName}`);
  }
  return match[1].toLowerCase();
}

function verifySbom(path, archiveName) {
  const size = lstatSync(path).size;
  if (size < 1 || size > MAX_SBOM_BYTES) {
    throw new Error(`SBOM for ${archiveName} must be between 1 byte and 16 MiB`);
  }

  let document;
  try {
    document = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new Error(`SBOM for ${archiveName} is not valid JSON`);
  }
  if (!document || Array.isArray(document) || typeof document !== "object") {
    throw new Error(`SBOM for ${archiveName} must be a JSON object`);
  }
  if (document.spdxVersion !== "SPDX-2.3" || document.dataLicense !== "CC0-1.0") {
    throw new Error(`SBOM for ${archiveName} must declare SPDX-2.3 and CC0-1.0`);
  }
  if (document.SPDXID !== "SPDXRef-DOCUMENT" || document.name !== archiveName) {
    throw new Error(`SBOM for ${archiveName} has the wrong document identity`);
  }
  if (typeof document.documentNamespace !== "string" ||
      !/^https?:\/\/[^\s]+$/.test(document.documentNamespace)) {
    throw new Error(`SBOM for ${archiveName} has an invalid document namespace`);
  }
  const created = document.creationInfo?.created;
  const creators = document.creationInfo?.creators;
  if (typeof created !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(created) ||
      !Array.isArray(creators) || creators.length < 1 ||
      creators.some((creator) => typeof creator !== "string" || creator.trim() === "")) {
    throw new Error(`SBOM for ${archiveName} has invalid creation metadata`);
  }
  if (!Array.isArray(document.packages)) {
    throw new Error(`SBOM for ${archiveName} must contain an SPDX packages array`);
  }
}

function inspectCommand(command, args, archiveName) {
  try {
    return execFileSync(command, args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 10_000,
      maxBuffer: 1024 * 1024,
    });
  } catch (error) {
    const detail = error.code === "ENOENT" ? `${command} is unavailable` : `${command} rejected it`;
    throw new Error(`could not inspect ${archiveName}: ${detail}`);
  }
}

function exactLines(output) {
  const normalized = output.replace(/\r\n/g, "\n").replace(/\n$/, "");
  return normalized === "" ? [] : normalized.split("\n");
}

function verifyArchiveMembers(path, archiveName) {
  const windows = archiveName.endsWith(".zip");
  const expected = windows ? ["phantom-mcp.exe", "phantom.exe"] : ["phantom", "phantom-mcp"];
  if (windows) {
    const members = exactLines(inspectCommand("unzip", ["-Z1", path], archiveName)).sort();
    if (members.length !== 2 || !members.every((name, index) => name === expected[index])) {
      throw new Error(`${archiveName} must contain exactly phantom.exe and phantom-mcp.exe`);
    }
    const listing = exactLines(inspectCommand("zipinfo", ["-l", path], archiveName));
    for (const name of expected) {
      const entries = listing.filter((line) => line.endsWith(` ${name}`));
      if (entries.length !== 1 || !entries[0].startsWith("-")) {
        throw new Error(`${archiveName} member ${name} must be one regular file`);
      }
    }
    return;
  }

  const members = exactLines(inspectCommand("tar", ["-tzf", path], archiveName)).sort();
  if (members.length !== 2 || !members.every((name, index) => name === expected[index])) {
    throw new Error(`${archiveName} must contain exactly phantom and phantom-mcp`);
  }
  const listing = exactLines(inspectCommand("tar", ["-tvzf", path], archiveName));
  if (listing.length !== 2 || listing.some((line) => !line.startsWith("-"))) {
    throw new Error(`${archiveName} members must be regular files`);
  }
}

export function verifyReleaseArtifacts(rootPath) {
  const root = resolve(rootPath);
  const files = walkFiles(root);
  const byName = new Map();
  for (const path of files) {
    const name = basename(path);
    const matches = byName.get(name) || [];
    matches.push(path);
    byName.set(name, matches);
  }

  const allowedNames = new Set([
    ...EXPECTED_ARCHIVES,
    ...EXPECTED_ARCHIVES.map((name) => `${name}.sha256`),
    ...EXPECTED_ARCHIVES.map((name) => `${name}.spdx.json`),
    "SHA256SUMS",
  ]);
  const unexpected = [...byName.keys()].filter((name) => !allowedNames.has(name)).sort();
  if (unexpected.length > 0) {
    throw new Error(`unexpected release artifact files: ${unexpected.join(", ")}`);
  }
  if (files.length !== allowedNames.size) {
    throw new Error(`expected exactly ${allowedNames.size} release files, found ${files.length}`);
  }

  const expectedAggregate = new Map();
  for (const archiveName of EXPECTED_ARCHIVES) {
    const archives = byName.get(archiveName) || [];
    const sidecars = byName.get(`${archiveName}.sha256`) || [];
    const sboms = byName.get(`${archiveName}.spdx.json`) || [];
    if (archives.length !== 1 || sidecars.length !== 1 || sboms.length !== 1) {
      throw new Error(`expected one archive, one sidecar, and one SBOM for ${archiveName}`);
    }
    const archiveSize = lstatSync(archives[0]).size;
    if (archiveSize < 1 || archiveSize > MAX_ARCHIVE_BYTES) {
      throw new Error(`release archive ${archiveName} must be between 1 byte and 100 MiB`);
    }
    const actual = sha256(archives[0]);
    const sidecar = parseChecksumFile(sidecars[0], archiveName);
    if (actual !== sidecar) throw new Error(`checksum mismatch for ${archiveName}`);
    verifyArchiveMembers(archives[0], archiveName);
    verifySbom(sboms[0], archiveName);
    expectedAggregate.set(archiveName, actual);
  }

  const aggregatePaths = byName.get("SHA256SUMS") || [];
  if (aggregatePaths.length !== 1) throw new Error("expected exactly one SHA256SUMS file");
  const aggregateLines = readFileSync(aggregatePaths[0], "utf8").trim().split(/\r?\n/);
  if (aggregateLines.length !== EXPECTED_ARCHIVES.length) {
    throw new Error(`SHA256SUMS must contain exactly ${EXPECTED_ARCHIVES.length} lines`);
  }
  const seen = new Set();
  for (const line of aggregateLines) {
    const match = line.match(/^([0-9a-f]{64})  ([^\r\n\s]+)$/i);
    if (!match) throw new Error("SHA256SUMS contains a malformed line");
    const name = match[2];
    if (!expectedAggregate.has(name) || seen.has(name)) {
      throw new Error(`SHA256SUMS contains an unexpected or duplicate entry: ${name}`);
    }
    if (match[1].toLowerCase() !== expectedAggregate.get(name)) {
      throw new Error(`SHA256SUMS checksum mismatch for ${name}`);
    }
    seen.add(name);
  }
  if (seen.size !== EXPECTED_ARCHIVES.length) {
    throw new Error("SHA256SUMS is missing an expected archive");
  }
  return { archives: EXPECTED_ARCHIVES.length, files: files.length };
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  if (process.argv.length !== 3) throw new Error("usage: verify-release-artifacts.mjs <artifacts-dir>");
  const result = verifyReleaseArtifacts(process.argv[2]);
  console.log(`release artifacts verified: ${result.archives} archives, ${result.archives} SBOMs, and ${result.files} exact files`);
}
