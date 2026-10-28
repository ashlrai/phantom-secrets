import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { lintChangelog } from "./lint-changelog.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const linter = join(repoRoot, "scripts", "release", "lint-changelog.mjs");

const BASE = "https://github.com/example/project";

function changelog({ sections, links }) {
  return [
    "# Changelog",
    "",
    ...sections.flatMap((section) => [section, "", "- entry", ""]),
    ...links.map(([label, url]) => `[${label}]: ${url}`),
    "",
  ].join("\n");
}

function standard({ versions = ["1.1.0", "1.0.0"], tagOldest = true } = {}) {
  const links = [["Unreleased", `${BASE}/compare/v${versions[0]}...HEAD`]];
  versions.forEach((version, index) => {
    const older = versions[index + 1];
    const url = older
      ? `${BASE}/compare/v${older}...v${version}`
      : tagOldest
        ? `${BASE}/releases/tag/v${version}`
        : `${BASE}/compare/v0.9.0...v${version}`;
    links.push([version, url]);
  });
  return changelog({
    sections: ["## [Unreleased]", ...versions.map((version) => `## [${version}] - 2026-09-01`)],
    links,
  });
}

function messages(text) {
  return lintChangelog(text).map((issue) => issue.message);
}

test("the repository changelog satisfies every rule", () => {
  const text = readFileSync(join(repoRoot, "CHANGELOG.md"), "utf8");
  assert.deepEqual(lintChangelog(text), []);
});

test("a well-formed changelog reports no issues", () => {
  assert.deepEqual(lintChangelog(standard()), []);
});

test("version headings must sort newest first", () => {
  const issues = lintChangelog(standard({ versions: ["1.0.0", "1.1.0"] }));
  assert.equal(issues.length, 1);
  assert.match(issues[0].message, /out of order/);
  assert.equal(issues[0].line, 11);
});

test("duplicate version headings are rejected", () => {
  const text = changelog({
    sections: ["## [Unreleased]", "## [1.0.0] - 2026-09-01", "## [1.0.0] - 2026-09-02"],
    links: [
      ["Unreleased", `${BASE}/compare/v1.0.0...HEAD`],
      ["1.0.0", `${BASE}/releases/tag/v1.0.0`],
    ],
  });
  assert.ok(messages(text).some((message) => message.includes("duplicate version heading")));
});

test("a version heading without a date is rejected", () => {
  const text = changelog({
    sections: ["## [Unreleased]", "## [1.0.0]"],
    links: [
      ["Unreleased", `${BASE}/compare/v1.0.0...HEAD`],
      ["1.0.0", `${BASE}/releases/tag/v1.0.0`],
    ],
  });
  const found = messages(text).filter((message) => message.includes("missing its"));
  assert.equal(found.length, 1);
  assert.match(found[0], /\[1\.0\.0\] is missing its " - YYYY-MM-DD" release date/);
});

for (const badDate of ["2026-02-30", "2026-13-01", "2026-00-10", "2025-02-29"]) {
  test(`impossible calendar date ${badDate} is rejected`, () => {
    const text = changelog({
      sections: [`## [1.0.0] - ${badDate}`],
      links: [["1.0.0", `${BASE}/releases/tag/v1.0.0`]],
    });
    assert.ok(messages(text).some((message) => message.includes("impossible date")));
  });
}

test("2024-02-29 was a real leap day and is accepted", () => {
  const text = changelog({
    sections: ["## [1.0.0] - 2024-02-29"],
    links: [["1.0.0", `${BASE}/releases/tag/v1.0.0`]],
  });
  assert.deepEqual(lintChangelog(text), []);
});

for (const [heading, pattern] of [
  ["## 1.0.0 - 2026-09-01", /level-2 heading must be/],
  ["## [v1.0.0] - 2026-09-01", /not a semantic version/],
  ["## [1.0] - 2026-09-01", /not a semantic version/],
  ["## [1.0.0] 2026-09-01", /must end with " - YYYY-MM-DD"/],
  ["## [1.0.0] - 2026-09-01 ", /extra whitespace/],
]) {
  test(`malformed heading ${JSON.stringify(heading)} is rejected`, () => {
    const text = changelog({
      sections: [heading],
      links: [["1.0.0", `${BASE}/releases/tag/v1.0.0`]],
    });
    assert.ok(
      messages(text).some((message) => pattern.test(message)),
      JSON.stringify(messages(text))
    );
  });
}

test("a dated Unreleased heading is rejected", () => {
  const text = changelog({
    sections: ["## [Unreleased] - 2026-09-01", "## [1.0.0] - 2026-09-01"],
    links: [
      ["Unreleased", `${BASE}/compare/v1.0.0...HEAD`],
      ["1.0.0", `${BASE}/releases/tag/v1.0.0`],
    ],
  });
  assert.ok(messages(text).some((message) => message.includes("must not carry a release date")));
});

test("Unreleased must come before every version heading", () => {
  const text = changelog({
    sections: ["## [1.0.0] - 2026-09-01", "## [Unreleased]"],
    links: [
      ["Unreleased", `${BASE}/compare/v1.0.0...HEAD`],
      ["1.0.0", `${BASE}/releases/tag/v1.0.0`],
    ],
  });
  assert.ok(messages(text).some((message) => message.includes("must be the first level-2 heading")));
});

test("every heading needs a link definition", () => {
  const text = changelog({
    sections: ["## [Unreleased]", "## [1.0.0] - 2026-09-01"],
    links: [["Unreleased", `${BASE}/compare/v1.0.0...HEAD`]],
  });
  assert.ok(messages(text).some((message) => message.includes('missing link definition "[1.0.0]')));
});

test("a version link must compare against the immediately older release", () => {
  const text = changelog({
    sections: ["## [Unreleased]", "## [1.2.0] - 2026-09-03", "## [1.1.0] - 2026-09-02", "## [1.0.0] - 2026-09-01"],
    links: [
      ["Unreleased", `${BASE}/compare/v1.2.0...HEAD`],
      ["1.2.0", `${BASE}/compare/v1.0.0...v1.2.0`],
      ["1.1.0", `${BASE}/compare/v1.0.0...v1.1.0`],
      ["1.0.0", `${BASE}/releases/tag/v1.0.0`],
    ],
  });
  const found = messages(text).filter((message) => message.includes("expected v"));
  assert.equal(found.length, 1);
  assert.match(found[0], /\[1\.2\.0\] link compares v1\.0\.0\.\.\.v1\.2\.0; expected v1\.1\.0\.\.\.v1\.2\.0/);
});

test("the Unreleased link must compare the newest release to HEAD", () => {
  const text = changelog({
    sections: ["## [Unreleased]", "## [1.0.0] - 2026-09-01"],
    links: [
      ["Unreleased", `${BASE}/compare/v0.9.0...HEAD`],
      ["1.0.0", `${BASE}/releases/tag/v1.0.0`],
    ],
  });
  assert.ok(
    messages(text).some((message) => message.includes("expected v1.0.0...HEAD")),
    JSON.stringify(messages(text))
  );
});

test("a link definition without a matching heading is rejected", () => {
  const text = changelog({
    sections: ["## [1.0.0] - 2026-09-01"],
    links: [
      ["1.0.0", `${BASE}/releases/tag/v1.0.0`],
      ["0.9.0", `${BASE}/releases/tag/v0.9.0`],
    ],
  });
  assert.ok(messages(text).some((message) => message.includes("link definition [0.9.0] has no matching heading")));
});

test("duplicate link definitions are rejected", () => {
  const text = changelog({
    sections: ["## [1.0.0] - 2026-09-01"],
    links: [
      ["1.0.0", `${BASE}/releases/tag/v1.0.0`],
      ["1.0.0", `${BASE}/releases/tag/v1.0.0`],
    ],
  });
  assert.ok(messages(text).some((message) => message.includes("duplicate link definition [1.0.0]")));
});

test("the oldest listed release may use a tag link or a compare link", () => {
  assert.deepEqual(lintChangelog(standard({ tagOldest: true })), []);
  assert.deepEqual(lintChangelog(standard({ tagOldest: false })), []);
});

test("a tag link on a non-oldest release is rejected", () => {
  const text = changelog({
    sections: ["## [Unreleased]", "## [1.1.0] - 2026-09-02", "## [1.0.0] - 2026-09-01"],
    links: [
      ["Unreleased", `${BASE}/compare/v1.1.0...HEAD`],
      ["1.1.0", `${BASE}/releases/tag/v1.1.0`],
      ["1.0.0", `${BASE}/releases/tag/v1.0.0`],
    ],
  });
  assert.ok(
    messages(text).some((message) => message.includes("a tag link is only valid on the oldest listed release"))
  );
});

test("links mixing repository bases are rejected", () => {
  const text = changelog({
    sections: ["## [Unreleased]", "## [1.1.0] - 2026-09-02", "## [1.0.0] - 2026-09-01"],
    links: [
      ["Unreleased", `${BASE}/compare/v1.1.0...HEAD`],
      ["1.1.0", `https://github.com/example/other/compare/v1.0.0...v1.1.0`],
      ["1.0.0", `${BASE}/releases/tag/v1.0.0`],
    ],
  });
  assert.ok(messages(text).some((message) => message.includes("earlier links use")));
});

test("headings and links inside fenced code blocks are ignored", () => {
  const text = changelog({
    sections: [
      "## [Unreleased]",
      "```",
      "## [9.9.9] - 1999-01-01",
      "[9.9.9]: https://elsewhere.example/compare/v9.9.8...v9.9.9",
      "```",
      "## [1.0.0] - 2026-09-01",
    ],
    links: [
      ["Unreleased", `${BASE}/compare/v1.0.0...HEAD`],
      ["1.0.0", `${BASE}/releases/tag/v1.0.0`],
    ],
  });
  assert.deepEqual(lintChangelog(text), []);
});

test("an empty changelog fails closed", () => {
  const issues = lintChangelog("# Changelog\n\nnothing here\n");
  assert.equal(issues.length, 1);
  assert.match(issues[0].message, /no "## \[Unreleased\]" or/);
});

test("the CLI exits nonzero and reports file:line for a bad file", () => {
  const dir = mkdtempSync(join(tmpdir(), "changelog-lint-"));
  const bad = join(dir, "CHANGELOG.md");
  writeFileSync(bad, "## [1.0.0] - 2026-09-01\n\n- entry\n");
  const result = spawnSync(process.execPath, [linter, bad], { encoding: "utf8" });
  assert.equal(result.status, 1);
  assert.match(result.stderr, new RegExp(`${bad.replaceAll("/", "\\/")}:1: `));
  assert.match(result.stderr, /missing link definition/);
});

test("the CLI passes on the repository changelog", () => {
  const result = spawnSync(process.execPath, [linter], { cwd: repoRoot, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /CHANGELOG\.md: ok/);
});

test("the CLI rejects extra arguments", () => {
  const result = spawnSync(process.execPath, [linter, "a", "b"], { encoding: "utf8" });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /usage: lint-changelog\.mjs/);
});
