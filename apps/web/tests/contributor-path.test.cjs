const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const web = path.resolve(__dirname, "..");
const repo = path.resolve(web, "../..");
const read = (file) => fs.readFileSync(file, "utf8");

const ANCHOR_URL =
  "https://github.com/ashlrai/phantom-secrets/blob/main/CONTRIBUTING.md#contribute-with-an-agent";

test("CONTRIBUTING.md still has the Contribute with an agent heading the site links to", () => {
  assert.match(read(path.join(repo, "CONTRIBUTING.md")), /^### Contribute with an agent$/m);
});

test("the docs hub and the ecosystem section link the fork-to-merge contributor path", () => {
  for (const file of ["src/app/docs/page.tsx", "src/components/landing/AshlrEcosystem.tsx"]) {
    assert.ok(read(path.join(web, file)).includes(ANCHOR_URL), `${file} must link ${ANCHOR_URL}`);
  }
});

test("the ecosystem section states the merge facts CONTRIBUTING.md states", () => {
  const component = read(path.join(web, "src/components/landing/AshlrEcosystem.tsx")).replace(/\s+/g, " ");
  const contributing = read(path.join(repo, "CONTRIBUTING.md")).replace(/\s+/g, " ");
  assert.match(component, /<code>CI Gate<\/code> is the only required check/);
  assert.match(contributing, /`CI Gate` is the only required check/);
  assert.match(component, /need no write access or repository secrets/);
  assert.match(contributing, /never need write access or repository secrets/);
});
