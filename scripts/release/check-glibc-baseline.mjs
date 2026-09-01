#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const NUMERIC_GLIBC_VERSION = /^\d+(?:\.\d+)+$/;

export function parseVersion(value, label = "version") {
  if (!NUMERIC_GLIBC_VERSION.test(value)) {
    throw new Error(`${label} must be a dotted numeric version`);
  }
  const parts = value.split(".").map((part) => Number(part));
  if (parts.some((part) => !Number.isSafeInteger(part))) {
    throw new Error(`${label} contains an unsupported numeric component`);
  }
  return parts;
}

export function compareVersions(left, right) {
  const leftParts = Array.isArray(left) ? left : parseVersion(left, "left version");
  const rightParts = Array.isArray(right) ? right : parseVersion(right, "right version");
  const length = Math.max(leftParts.length, rightParts.length);
  for (let index = 0; index < length; index += 1) {
    const difference = (leftParts[index] ?? 0) - (rightParts[index] ?? 0);
    if (difference !== 0) return Math.sign(difference);
  }
  return 0;
}

export function parseGlibcRequirements(readelfOutput) {
  const symbols = readelfOutput.match(/\bGLIBC_[A-Za-z0-9_.-]+\b/g) ?? [];
  const unsupported = [...new Set(symbols)]
    .filter((symbol) => !NUMERIC_GLIBC_VERSION.test(symbol.slice("GLIBC_".length)))
    .sort();
  if (unsupported.length > 0) {
    throw new Error(`unsupported GLIBC version requirement: ${unsupported.join(", ")}`);
  }

  const versions = [...new Set(symbols.map((symbol) => symbol.slice("GLIBC_".length)))];
  versions.sort(compareVersions);
  if (versions.length === 0) {
    throw new Error("ELF has no numeric GLIBC version requirements; refusing a vacuous compatibility pass");
  }
  return versions;
}

export function evaluateGlibcBaseline(readelfOutput, baseline) {
  parseVersion(baseline, "GLIBC baseline");
  const required = parseGlibcRequirements(readelfOutput);
  const highest = required.at(-1);
  if (compareVersions(highest, baseline) > 0) {
    throw new Error(`requires GLIBC_${highest}, which exceeds the GLIBC_${baseline} ceiling`);
  }
  return { baseline, highest, required };
}

export function inspectBinary(binaryPath, baseline) {
  let output;
  try {
    output = execFileSync("readelf", ["--version-info", "--wide", binaryPath], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 10_000,
      maxBuffer: 4 * 1024 * 1024,
    });
  } catch (error) {
    const detail = error.code === "ENOENT" ? "readelf is unavailable" : "readelf rejected the file";
    throw new Error(`${binaryPath}: ${detail}`);
  }
  return evaluateGlibcBaseline(output, baseline);
}

function parseArguments(args) {
  if (args.length < 3 || args[0] !== "--baseline") {
    throw new Error("usage: check-glibc-baseline.mjs --baseline <version> <ELF> [<ELF> ...]");
  }
  const baseline = args[1];
  parseVersion(baseline, "GLIBC baseline");
  return { baseline, binaries: args.slice(2) };
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  const { baseline, binaries } = parseArguments(process.argv.slice(2));
  for (const binary of binaries) {
    const result = inspectBinary(binary, baseline);
    console.log(`${binary}: highest requirement GLIBC_${result.highest} (ceiling GLIBC_${baseline})`);
  }
}
