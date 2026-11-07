#!/usr/bin/env node
/**
 * Record today's public ecosystem star total.
 *
 *   node apps/web/scripts/record-star-snapshot.mjs --out apps/web/src/lib/star-history.json
 *   node apps/web/scripts/record-star-snapshot.mjs --out /tmp/star-history.json --prior /tmp/prior/star-history.json
 *
 * Reads apps/web/ecosystem-repos.json. Uses PHANTOM_STARS_GITHUB_TOKEN or
 * GITHUB_TOKEN when set, otherwise the unauthenticated GitHub API.
 * A failed or partial read exits without writing.
 */
import { createRequire } from "node:module";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const {
  fetchPublicStars,
  githubToken,
  mergeHistories,
  parseHistory,
  upsertSnapshot,
} = require("../src/lib/stars-core.js");

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export function readHistory(path) {
  if (!path) return null;
  try {
    return parseHistory(JSON.parse(readFileSync(path, "utf8")));
  } catch {
    return null;
  }
}

function argument(name) {
  const index = process.argv.indexOf(name);
  return index === -1 ? null : process.argv[index + 1] ?? null;
}

export async function recordSnapshot({ config, histories, fetchImpl, token, now }) {
  const live = await fetchPublicStars({ config, fetchImpl, token, now });
  if (!live.ok) return live;
  const merged = mergeHistories(histories);
  const history = upsertSnapshot(merged.snapshots.length > 0 ? merged : { schemaVersion: 1, snapshots: [] }, live.snapshot);
  if (!parseHistory(history)) return { ok: false, reason: "history" };
  return { ok: true, history };
}

async function main() {
  const out = argument("--out");
  if (!out) {
    console.error("usage: record-star-snapshot.mjs --out <file> [--prior <file>]");
    process.exit(1);
  }
  const config = JSON.parse(readFileSync(resolve(root, "ecosystem-repos.json"), "utf8"));
  const bundled = readHistory(resolve(root, "src/lib/star-history.json"));
  const prior = readHistory(argument("--prior"));
  const result = await recordSnapshot({
    config,
    histories: [bundled, prior],
    fetchImpl: globalThis.fetch,
    token: githubToken(process.env),
  });
  if (!result.ok) {
    console.error(`star snapshot failed: ${result.reason}${result.missing ? ` (${result.missing})` : ""}`);
    process.exit(1);
  }
  const history = result.history;
  writeFileSync(out, `${JSON.stringify(history, null, 2)}\n`);
  const latest = history.snapshots[history.snapshots.length - 1];
  console.log(JSON.stringify({ date: latest.date, total: latest.total, repos: Object.keys(latest.repos).length }));
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : "star snapshot failed");
    process.exit(1);
  });
}
