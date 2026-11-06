import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const agents = readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), "../AGENTS.md"), "utf8");
const heading = "## Hot-file rule";
const start = agents.indexOf(heading);
const next = agents.indexOf("\n## ", start + 1);
const section = start < 0 ? "" : agents.slice(start, next < 0 ? undefined : next);
const flat = section.replace(/\s+/g, " ");

test("AGENTS.md has a hot-file rule section", () => {
  assert.ok(start >= 0, "missing '## Hot-file rule' section in AGENTS.md");
});

test("rule 1: new docs do not edit docs/README.md", () => {
  assert.match(flat, /A new doc does not edit `docs\/README\.md`/);
});

test("rule 2: new web tests go in a new file, never appended to an existing .cjs file", () => {
  assert.match(flat, /A new web test goes in a new file/);
  assert.match(flat, /Never append it to an existing `\.cjs` test file/);
});

test("the named hot files exist so the rule cannot rot silently", () => {
  for (const f of ["docs/README.md", "apps/web/tests/quick-start-keyboard.test.cjs"]) {
    const path = resolve(dirname(fileURLToPath(import.meta.url)), "..", f);
    assert.doesNotThrow(() => readFileSync(path), `${f} referenced by the rule is missing`);
  }
});
