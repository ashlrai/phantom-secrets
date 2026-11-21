// The site's llms.txt and llms-full.txt are served at the web root, so an agent
// can start from them without opening the repository. They must carry the same
// contributor facts as the repository entry points that
// scripts/agent-entry-points-pre-push.test.mjs guards, written for a fork
// (`upstream/main`). Pull request CI runs neither this web suite nor the docs
// drift checks, so this test is the guard; run it with `npm test` in apps/web.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const web = path.resolve(__dirname, "..");
const repo = path.resolve(web, "../..");

const ANCHOR_URL =
  "https://github.com/ashlrai/phantom-secrets/blob/main/CONTRIBUTING.md#contribute-with-an-agent";

const REQUIRED = [
  "node scripts/changelog-fold.mjs --check",
  "git diff upstream/main...HEAD | perl .github/tests/secret-shape/scrub.pl --check --allow-fixtures",
  "node --test scripts/release/readme-mcp-catalog.test.mjs",
  "node --test scripts/docs-distribution.test.mjs",
  "node --test scripts/hot-file-rule.test.mjs",
  "cargo test --locked -p phantom-secrets --test docs_command_flags_test",
];

for (const file of ["public/llms.txt", "public/llms-full.txt"]) {
  const text = fs.readFileSync(path.join(web, file), "utf8");
  const flat = text.replace(/\s+/g, " ");

  test(`${file} links the fork-to-merge contributor path`, () => {
    assert.ok(text.includes(ANCHOR_URL), `${file} must link ${ANCHOR_URL}`);
  });

  test(`${file} names the pre-push checks and every docs drift check`, () => {
    for (const command of REQUIRED) {
      assert.ok(flat.includes(command), `${file} is missing \`${command}\``);
    }
  });

  test(`${file} says pull request CI skips the Rust tests and the docs drift checks`, () => {
    assert.match(flat, /pull request CI does not run the Rust test suite/);
    assert.match(flat, /run the docs drift checks instead, which pull request CI also skips/);
  });
}

test("the scripts and test the site's contributor path names still exist", () => {
  for (const file of [
    "scripts/changelog-fold.mjs",
    ".github/tests/secret-shape/scrub.pl",
    "scripts/release/readme-mcp-catalog.test.mjs",
    "scripts/docs-distribution.test.mjs",
    "scripts/hot-file-rule.test.mjs",
    "crates/phantom-cli/tests/docs_command_flags_test.rs",
  ]) {
    assert.ok(fs.existsSync(path.join(repo, file)), `${file} is missing`);
  }
});
