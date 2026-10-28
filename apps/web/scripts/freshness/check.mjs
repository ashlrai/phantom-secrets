#!/usr/bin/env node

// Drift check: exit 0 when every marked `fresh:` block matches the output
// generated from the repository's sources, exit 1 when a page, doc, or
// sitemap shows a stale version, command, or list.

import { readFileSync } from "node:fs";
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

export function checkAll(root) {
  const ctx = loadSources(root);
  const stale = [];
  for (const file of TARGETS.keys()) {
    const before = readFileSync(join(root, file), "utf8");
    const { drift } = applyBlocks(before, file, ctx);
    for (const entry of drift) {
      stale.push({ file, ...entry });
    }
  }
  return stale;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    const stale = checkAll(parseRoot(process.argv.slice(2)));
    if (stale.length === 0) {
      console.log("freshness: all generated blocks are current");
    } else {
      for (const entry of stale) {
        console.error(`freshness: ${entry.file} block ${entry.block} is stale`);
        const expected = entry.expected.split("\n");
        const actual = entry.actual.split("\n");
        const width = Math.max(expected.length, actual.length);
        for (let i = 0; i < width; i += 1) {
          if (expected[i] !== actual[i]) {
            console.error(`  - ${actual[i] ?? ""}`);
            console.error(`  + ${expected[i] ?? ""}`);
          }
        }
      }
      console.error(
        "freshness: run `node apps/web/scripts/freshness/sync.mjs` to regenerate",
      );
      process.exit(1);
    }
  } catch (error) {
    console.error(`freshness: ${error.message}`);
    process.exit(1);
  }
}
