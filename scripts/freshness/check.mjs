#!/usr/bin/env node

// Verify every `fresh:` marked block matches what sync.mjs would
// generate. Usage:
//
//   node scripts/freshness/check.mjs [--root DIR]
//
// Exits 0 when all blocks are fresh; exits 1 and prints each stale block
// or structural error otherwise. Intended for CI so docs drift fails the
// build before it ships.

import { dirname, resolve } from "node:path";
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
    console.log("usage: check.mjs [--root DIR]");
    console.log("exits nonzero when any <!-- fresh:begin name --> block is stale");
    return 0;
  }

  const ctx = loadSources(opts.root);
  const targets = collectTargets(opts.root);

  const problems = [];
  let rendered = 0;
  for (const rel of targets) {
    let plan;
    try {
      plan = planFile(opts.root, rel, ctx);
    } catch (err) {
      problems.push(err.message);
      continue;
    }
    rendered += plan.blocks.length;
    for (const block of plan.blocks) {
      if (block.changed) {
        problems.push(`${rel}:${block.line}: fresh block '${block.name}' is stale`);
      }
    }
  }

  if (problems.length > 0) {
    for (const problem of problems) {
      console.error(problem);
    }
    console.error(
      `freshness check failed: ${problems.length} problem(s); run node scripts/freshness/sync.mjs`,
    );
    return 1;
  }

  console.log(
    `freshness check passed: ${rendered} block(s) fresh across ${targets.length} file(s)`,
  );
  return 0;
}

try {
  process.exit(main());
} catch (err) {
  console.error(`freshness check failed: ${err.message}`);
  process.exit(1);
}
