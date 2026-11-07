import { test } from "node:test";
import { strictEqual } from "node:assert";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

const LOCKFILE = resolve(__dirname, "..", "apps", "web", "package-lock.json");
const FLOOR = "11.0.1";

function semverGreaterOrEqual(a, b) {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const va = pa[i] || 0;
    const vb = pb[i] || 0;
    if (va > vb) return true;
    if (va < vb) return false;
  }
  return true; // equal
}

test("apps/web minimatch is >= " + FLOOR, () => {
  const raw = readFileSync(LOCKFILE, "utf8");
  const lp = JSON.parse(raw);
  const minimatchVersion =
    lp.packages && lp.packages["node_modules/minimatch"]
      ? lp.packages["node_modules/minimatch"].version
      : null;

  strictEqual(
    minimatchVersion,
    null ? "not found" : minimatchVersion,
    "minimatch entry exists in lockfile",
  );

  strictEqual(
    typeof minimatchVersion,
    "string",
    "minimatch version is a string",
  );

  strictEqual(
    semverGreaterOrEqual(minimatchVersion, FLOOR),
    true,
    "minimatch " + minimatchVersion + " >= " + FLOOR,
  );
});
