// Every file a coding agent may start from must point at the contributor path,
// say that pull request CI does not run the Rust test suite, and name the two
// pre-push checks, so an agent that begins in Cursor, Copilot,
// Devin, Claude Code, or an llms.txt reader does not push a malformed changelog
// fragment or a token-shaped string. Pull request CI validates neither the
// fragment format nor these docs, so this test is the guard.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const ENTRY_POINTS = [
  "AGENTS.md",
  "CLAUDE.md",
  "CONTRIBUTING.md",
  "README.md",
  "llms.txt",
  "docs/llms.txt",
  "docs/llms-full.txt",
  ".cursorrules",
  ".github/copilot-instructions.md",
  ".github/PULL_REQUEST_TEMPLATE.md",
  ".devin/wiki.json",
];

const FRAGMENT_CHECK = "node scripts/changelog-fold.mjs --check";
const SECRET_SHAPE_SCAN =
  "git diff main...HEAD | perl .github/tests/secret-shape/scrub.pl --check --allow-fixtures";

const DOCS_DRIFT_CHECKS = [
  "node --test scripts/release/readme-mcp-catalog.test.mjs",
  "node --test scripts/docs-distribution.test.mjs",
  "node --test scripts/hot-file-rule.test.mjs",
  "cargo test --locked -p phantom-secrets --test docs_command_flags_test",
];

const NON_SUITE_DOC_CHECKS = [
  "bash scripts/test-docs-agents.sh",
  "node scripts/freshness/check.mjs",
];

const EDITED_FILE_SUITES = /every suite that reads the file (you|they) edited/i;
const SUITE_LOOKUP = /git grep -l -F \S+ -- '\*\.test\.\*'/;

function assertNamesEditedFileSuites(file, text) {
  const flat = text.replace(/\s+/g, " ");
  assert.match(flat, EDITED_FILE_SUITES, `${file} does not say to run every suite that reads the edited file`);
  assert.match(flat, SUITE_LOOKUP, `${file} does not show how to list those suites with git grep`);
}

for (const file of ENTRY_POINTS) {
  const text = readFileSync(resolve(root, file), "utf8");

  test(`${file} names the changelog fragment check`, () => {
    assert.ok(text.includes(FRAGMENT_CHECK), `${file} is missing \`${FRAGMENT_CHECK}\``);
  });

  test(`${file} names the local Secret-shape scan`, () => {
    assert.ok(text.includes(SECRET_SHAPE_SCAN), `${file} is missing the Secret-shape scan command`);
  });

  test(`${file} tells fork contributors to diff against upstream/main`, () => {
    assert.ok(text.includes("upstream/main"), `${file} does not mention upstream/main`);
  });

  // Pull request CI skips the Rust tests, so an agent that does not learn this
  // opens a pull request with no test evidence. Whitespace is normalized
  // because each file wraps the sentence differently.
  test(`${file} says pull request CI does not run the Rust test suite`, () => {
    assert.match(
      text.replace(/\s+/g, " "),
      /does not run the Rust test suite/i,
      `${file} does not say pull request CI skips the Rust test suite`,
    );
  });

  // Pull request CI skips the docs drift checks too, so an agent making a
  // docs-only change must learn them from whichever file it started in.
  test(`${file} names every docs drift check`, () => {
    for (const check of DOCS_DRIFT_CHECKS) {
      assert.ok(text.includes(check), `${file} is missing \`${check}\``);
    }
  });

  // The four drift checks do not cover every suite that reads a doc: some
  // live in apps/web/tests/, which only the daily web job runs. An agent must
  // learn to find and run them from whichever file it started in.
  test(`${file} says to run every suite that reads the edited file`, () => {
    assertNamesEditedFileSuites(file, text);
  });

  // Two doc checks are not named *.test.*, so the git grep lookup above
  // misses them and pull request CI runs neither. Every entry point names
  // both so an agent editing docs/agents.md or a freshness block runs them.
  test(`${file} names the doc checks the suite search misses`, () => {
    for (const check of NON_SUITE_DOC_CHECKS) {
      assert.ok(text.includes(check), `${file} is missing \`${check}\``);
    }
  });

  test(`${file} points at the contributor path`, () => {
    assert.match(text, /Contribute with an agent|contribute-with-an-agent/i);
  });
}

test("the commands these entry points name still exist", () => {
  for (const f of [
    "scripts/changelog-fold.mjs",
    ".github/tests/secret-shape/scrub.pl",
    "scripts/release/readme-mcp-catalog.test.mjs",
    "scripts/docs-distribution.test.mjs",
    "scripts/hot-file-rule.test.mjs",
    "crates/phantom-cli/tests/docs_command_flags_test.rs",
    "scripts/test-docs-agents.sh",
    "scripts/freshness/check.mjs",
  ]) {
    assert.doesNotThrow(() => readFileSync(resolve(root, f)), `${f} is missing`);
  }
});

// The site serves these at the web root, so an agent may start from them too.
// apps/web/tests/llms-contributor-path.test.cjs guards their other facts.
for (const file of ["apps/web/public/llms.txt", "apps/web/public/llms-full.txt"]) {
  const text = readFileSync(resolve(root, file), "utf8");
  test(`${file} says to run every suite that reads the edited file`, () => {
    assertNamesEditedFileSuites(file, text);
  });
}
