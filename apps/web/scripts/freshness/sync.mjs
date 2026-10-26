#!/usr/bin/env node

// Rewrite every marked `fresh:` block in the target files with freshly
// generated content. `check.mjs` is the read-only twin; run it in CI.

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { applyBlocks, TARGETS } from "./blocks.mjs";
import { loadSources } from "./sources.mjs";

const defaultRoot = join(dirname(fileURLToPath(import.meta.url)), "../../../..");

function parseRoot(argv) {
  const flagIndex = argv.indexOf("--root");
  if (flagIndex === -1) return defaultRoot;
  const root = argv[flagIndex + 1];
  if (!root) {
    throw new Error("--root requires a directory");
  }
  return root;
}

export function syncAll(root) {
  const ctx = loadSources(root);
  const changed = [];
  for (const file of TARGETS.keys()) {
    const before = readFileSync(join(root, file), "utf8");
    const { content, drift } = applyBlocks(before, file, ctx);
    if (drift.length > 0) {
      writeFileSync(join(root, file), content);
      changed.push({ file, blocks: drift.map((entry) => entry.block) });
    }
  }
  return changed;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    const changed = syncAll(parseRoot(process.argv.slice(2)));
    if (changed.length === 0) {
      console.log("freshness: all generated blocks already current");
    } else {
      for (const entry of changed) {
        console.log(`freshness: rewrote ${entry.file} (${entry.blocks.join(", ")})`);
      }
    }
  } catch (error) {
    console.error(`freshness: ${error.message}`);
    process.exit(1);
  }
}
