#!/usr/bin/env node

// Regenerate every `fresh:` marked block from the repository's
// source-of-truth release metadata. Usage:
//
//   node scripts/freshness/sync.mjs [--root DIR]
//
// Exits 0 after writing; exits nonzero when the sources disagree, a
// marked block is structurally broken, or a file cannot be written.

import { writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { collectTargets, planFile } from "./blocks.mjs";
import { loadSources } from "./sources.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

function parseArgs(argv) {
  const opts = { root: repoRoot };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--root" && i + 1 < argv.length) {
      opts.root = resolve(argv[i + 1]);
      i += 1;
    } else if (arg === "--help" || arg === "-h") {
      opts.help = true;
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  return opts;
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    console.log("usage: sync.mjs [--root DIR]");
    console.log("regenerates <!-- fresh:begin name --> ... <!-- fresh:end --> blocks");
    return 0;
  }

  const ctx = loadSources(opts.root);
  const targets = collectTargets(opts.root);

  // Render every file before writing anything so a broken marker aborts
  // the run without leaving a half-synced tree.
  const plans = targets.map((rel) => planFile(opts.root, rel, ctx));

  const updated = [];
  let rendered = 0;
  for (const plan of plans) {
    rendered += plan.blocks.length;
    if (!plan.changed) continue;
    writeFileSync(join(opts.root, plan.rel), plan.after);
    updated.push(plan);
  }

  for (const plan of updated) {
    const stale = plan.blocks.filter((block) => block.changed);
    console.log(`updated ${plan.rel} (${stale.length} block(s))`);
  }
  const noun = updated.length === 1 ? "file" : "files";
  console.log(
    `freshness sync complete: ${rendered} block(s) across ${plans.length} ${noun}` +
      (updated.length > 0
        ? `; ${updated.length} ${updated.length === 1 ? "file" : "files"} updated`
        : "; all blocks already fresh"),
  );
  return 0;
}

try {
  process.exit(main());
} catch (err) {
  console.error(`freshness sync failed: ${err.message}`);
  process.exit(1);
}
