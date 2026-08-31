#!/usr/bin/env node

import { lstatSync, readFileSync, readdirSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

function filesByBasename(rootPath, label) {
  const root = resolve(rootPath);
  const files = new Map();

  function walk(current) {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const path = join(current, entry.name);
      const stat = lstatSync(path);
      if (stat.isSymbolicLink()) {
        throw new Error(`${label} release artifact must not be a symlink: ${path}`);
      }
      if (stat.isDirectory()) {
        walk(path);
        continue;
      }
      if (!stat.isFile()) {
        throw new Error(`${label} release artifact must be a regular file: ${path}`);
      }

      const name = basename(path);
      if (files.has(name)) {
        throw new Error(`${label} release artifacts contain duplicate basename: ${name}`);
      }
      files.set(name, path);
    }
  }

  walk(root);
  return files;
}

export function compareReleaseArtifacts(trustedRoot, hostedRoot) {
  const trusted = filesByBasename(trustedRoot, "trusted");
  const hosted = filesByBasename(hostedRoot, "hosted");
  const trustedNames = [...trusted.keys()].sort();
  const hostedNames = [...hosted.keys()].sort();

  const missing = trustedNames.filter((name) => !hosted.has(name));
  const extra = hostedNames.filter((name) => !trusted.has(name));
  if (missing.length > 0 || extra.length > 0) {
    throw new Error(
      `release artifact name set mismatch; missing=${missing.join(",")} extra=${extra.join(",")}`,
    );
  }

  for (const name of trustedNames) {
    if (!readFileSync(trusted.get(name)).equals(readFileSync(hosted.get(name)))) {
      throw new Error(`hosted release artifact differs from trusted build: ${name}`);
    }
  }

  return { files: trustedNames.length };
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  if (process.argv.length !== 4) {
    throw new Error(
      "usage: compare-release-artifacts.mjs <trusted-artifacts-dir> <hosted-artifacts-dir>",
    );
  }
  const result = compareReleaseArtifacts(process.argv[2], process.argv[3]);
  console.log(`verified ${result.files} hosted release artifacts byte-for-byte`);
}
