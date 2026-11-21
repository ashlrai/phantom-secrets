// Keeps changelog.d/README.md in step with scripts/changelog-fold.mjs: every
// rule the README states is exercised here against a throwaway --root, so the
// repository's own CHANGELOG.md and fragments are never touched.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const repo = join(dirname(fileURLToPath(import.meta.url)), "..");
const script = join(repo, "scripts", "changelog-fold.mjs");
const readme = readFileSync(join(repo, "changelog.d", "README.md"), "utf8");
const CHANGELOG = "# Changelog\n\n## [Unreleased]\n\n### Fixed\n\n- older entry\n";

function run(fragments, args = ["--check"], changelog = CHANGELOG) {
  const root = mkdtempSync(join(tmpdir(), "changelog-fold-"));
  try {
    mkdirSync(join(root, "changelog.d"));
    writeFileSync(join(root, "changelog.d", "README.md"), "# not folded\n");
    for (const [name, body] of Object.entries(fragments)) {
      writeFileSync(join(root, "changelog.d", name), body);
    }
    writeFileSync(join(root, "CHANGELOG.md"), changelog);
    const r = spawnSync(process.execPath, [script, ...args, "--root", root], { encoding: "utf8" });
    return {
      status: r.status,
      out: r.stdout + r.stderr,
      changelog: readFileSync(join(root, "CHANGELOG.md"), "utf8"),
      left: readdirSync(join(root, "changelog.d")).sort(),
    };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test("the README lists exactly the section names the script accepts", () => {
  const src = readFileSync(script, "utf8");
  const sections = JSON.parse(src.match(/const SECTIONS = (\[[^\]]*\]);/)[1]);
  for (const s of sections) {
    assert.ok(readme.includes(`\`${s}\``), `README must list section ${s}`);
    assert.equal(run({ "ok.md": `### ${s} (topic)\n\n- entry\n` }).status, 0, s);
  }
  assert.equal(run({ "ok.md": "### Improved\n\n- entry\n" }).status, 1);
});

test("the README example fragment passes and prints the documented message", () => {
  const example = readme.match(/```markdown\n([\s\S]*?)```/)[1];
  const r = run({ "512.md": example });
  assert.equal(r.status, 0, r.out);
  assert.match(r.out, /changelog-fold: 1 fragment\(s\) valid \(check only\)/);
  assert.match(readme, /changelog-fold: N fragment\(s\) valid \(check only\)/);
});

test("each documented rule fails the check with the file name", () => {
  const cases = {
    "Bad_Name.md": "### Fixed\n\n- entry\n",
    "empty.md": "\n",
    "first-line.md": "- entry\n\n### Fixed\n\n- entry\n",
    "h2.md": "### Fixed\n\n## Release\n\n- entry\n",
    "unknown.md": "### Fixed\n\n- entry\n\n### Notes\n\n- entry\n",
    "512.md": "### Fixed\n\nprose only\n",
    "-leading-dash.md": "### Fixed\n\n- entry\n",
    "no-space.md": "### Fixed\n\n-entry\n",
  };
  for (const [name, body] of Object.entries(cases)) {
    const r = run({ [name]: body });
    assert.equal(r.status, 1, `${name} should fail`);
    assert.match(r.out, new RegExp(`changelog-fold: ${name.replace(".", "\\.")}: `));
  }
  assert.match(run({ "512.md": cases["512.md"] }).out, /changelog-fold: 512\.md: needs at least one bullet/);
  assert.match(readme, /`changelog-fold: 512\.md: needs at least one bullet`/);
});

test("files not ending in lowercase .md are skipped, as the README warns", () => {
  assert.match(readme, /`512\.txt` or `512\.MD` is skipped without an error/);
  const checked = run({ "512.txt": "not a fragment\n", "513.MD": "### Fixed\n\n- entry\n" });
  assert.equal(checked.status, 0, checked.out);
  assert.match(checked.out, /changelog-fold: 0 fragment\(s\) valid \(check only\)/);
  const folded = run({ "512.txt": "### Fixed\n\n- skipped entry\n" }, []);
  assert.equal(folded.status, 0, folded.out);
  assert.ok(!folded.changelog.includes("skipped entry"));
  assert.deepEqual(folded.left, ["512.txt", "README.md"]);
});

test("a missing Unreleased heading fails and changes nothing", () => {
  const r = run({ "a.md": "### Fixed\n\n- entry\n" }, [], "# Changelog\n");
  assert.equal(r.status, 1);
  assert.equal(r.changelog, "# Changelog\n");
  assert.deepEqual(r.left, ["README.md", "a.md"]);
});

test("folding inserts fragments by file name at the top of Unreleased and deletes them", () => {
  const r = run({ "b.md": "### Added\n\n- second\n", "a.md": "### Fixed\n\n- first\n" }, []);
  assert.equal(r.status, 0, r.out);
  const first = r.changelog.indexOf("- first");
  const second = r.changelog.indexOf("- second");
  const older = r.changelog.indexOf("- older entry");
  assert.ok(r.changelog.indexOf("## [Unreleased]") < first && first < second && second < older);
  assert.deepEqual(r.left, ["README.md"]);
});
