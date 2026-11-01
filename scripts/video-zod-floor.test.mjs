import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

// GHSA-mrhx-c7xc-m3w5 (high): zod < 4.6.6 can exhaust memory validating
// oversized constrained collections. Every zod install recorded in
// video/package-lock.json must resolve to 4.6.6 or later.
const FLOOR = "4.6.6";
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const lockPath = join(root, "video", "package-lock.json");

export function compareVersions(a, b) {
  const parse = v => {
    const dash = v.indexOf("-");
    const core = dash === -1 ? v : v.slice(0, dash);
    return { nums: core.split(".").map(n => Number(n) || 0), pre: dash === -1 ? [] : v.slice(dash + 1).split(".") };
  };
  const pa = parse(a);
  const pb = parse(b);
  for (let i = 0; i < Math.max(pa.nums.length, pb.nums.length); i++) {
    const d = (pa.nums[i] ?? 0) - (pb.nums[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  if (pa.pre.length === 0 || pb.pre.length === 0) return pa.pre.length === pb.pre.length ? 0 : pa.pre.length === 0 ? 1 : -1;
  for (let i = 0; i < Math.max(pa.pre.length, pb.pre.length); i++) {
    const xa = pa.pre[i];
    const xb = pb.pre[i];
    if (xa === undefined) return -1;
    if (xb === undefined) return 1;
    if (xa === xb) continue;
    const aNum = /^\d+$/.test(xa);
    const bNum = /^\d+$/.test(xb);
    if (aNum && bNum) return Number(xa) < Number(xb) ? -1 : 1;
    if (aNum !== bNum) return aNum ? -1 : 1;
    return xa < xb ? -1 : 1;
  }
  return 0;
}

export function zodInstalls(lock) {
  const installs = [];
  for (const [path, entry] of Object.entries(lock.packages ?? {})) {
    if (path === "node_modules/zod" || path.endsWith("/node_modules/zod")) {
      installs.push({ path, version: entry.version });
    }
  }
  const walk = (deps, trail) => {
    for (const [name, entry] of Object.entries(deps ?? {})) {
      const at = trail ? `${trail}>${name}` : name;
      if (name === "zod" && entry.version) installs.push({ path: `dependencies:${at}`, version: entry.version });
      walk(entry.dependencies, at);
    }
  };
  walk(lock.dependencies, "");
  return installs;
}

test("compareVersions orders release and prerelease triples", () => {
  assert.equal(compareVersions("4.6.6", "4.6.6"), 0);
  assert.equal(compareVersions("4.6.5", "4.6.6"), -1);
  assert.equal(compareVersions("4.6.7", "4.6.6"), 1);
  assert.equal(compareVersions("3.25.76", "4.6.6"), -1);
  assert.equal(compareVersions("4.10.0", "4.6.6"), 1);
  assert.equal(compareVersions("5.0.0", "4.6.6"), 1);
  assert.equal(compareVersions("4.6.6-canary.1", "4.6.6"), -1);
});

test("zodInstalls finds top-level and nested lockfile entries", () => {
  const installs = zodInstalls({
    packages: {
      "": {},
      "node_modules/zod": { version: "4.6.7" },
      "node_modules/a/node_modules/zod": { version: "3.25.76" },
      "node_modules/zod-not": { version: "9.9.9" },
    },
    dependencies: { zod: { version: "4.6.7", dependencies: { zod: { version: "4.0.0" } } } },
  });
  assert.deepEqual(
    installs.map(i => `${i.path}@${i.version}`).sort(),
    [
      "dependencies:zod@4.6.7",
      "dependencies:zod>zod@4.0.0",
      "node_modules/a/node_modules/zod@3.25.76",
      "node_modules/zod@4.6.7",
    ].sort(),
  );
});

test(`every zod in video/package-lock.json is >= ${FLOOR}`, () => {
  const lock = JSON.parse(readFileSync(lockPath, "utf8"));
  const installs = zodInstalls(lock);
  assert.ok(installs.length > 0, "no zod package entries found in video/package-lock.json");
  const vulnerable = installs.filter(i => compareVersions(i.version, FLOOR) < 0);
  assert.deepEqual(vulnerable, [],
    `zod below ${FLOOR} (GHSA-mrhx-c7xc-m3w5): ${vulnerable.map(i => `${i.path}@${i.version}`).join(", ")}`);
});
