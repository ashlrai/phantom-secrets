import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

// Issue forms are read by first-time contributors. A dropdown option that
// names a release (for example "Current 0.7.7 source") goes stale on the next
// release, so options stay version-free and ask the reporter for the exact
// version or commit SHA instead.
const dir = resolve(dirname(fileURLToPath(import.meta.url)), "../.github/ISSUE_TEMPLATE");
const forms = readdirSync(dir).filter((f) => f.endsWith(".yml") && f !== "config.yml");
const pinnedVersion = /\bv?\d+\.\d+\.\d+\b/;

test("issue forms exist", () => {
  for (const f of ["bug_report.yml", "documentation.yml", "feature_request.yml"]) {
    assert.ok(forms.includes(f), `missing .github/ISSUE_TEMPLATE/${f}`);
  }
});

test("issue form dropdown options do not pin a release version", () => {
  for (const f of forms) {
    const lines = readFileSync(join(dir, f), "utf8").split("\n");
    let inOptions = false;
    for (const [i, line] of lines.entries()) {
      if (/^\s+options:\s*$/.test(line)) { inOptions = true; continue; }
      if (inOptions && !/^\s+- /.test(line)) inOptions = false;
      if (inOptions) {
        assert.doesNotMatch(line, pinnedVersion, `${f}:${i + 1} pins a version in a dropdown option`);
      }
    }
  }
});

test("documentation form asks for the exact version or commit SHA", () => {
  const doc = readFileSync(join(dir, "documentation.yml"), "utf8");
  assert.match(doc, /exact release version or commit SHA/);
});
