#!/usr/bin/env node
// Fold changelog.d/*.md fragments into CHANGELOG.md under "## [Unreleased]".
// Deterministic: fragments are inserted in byte order of their file names,
// at the top of the Unreleased section, then deleted. Validates everything
// before writing anything. Usage: node scripts/changelog-fold.mjs [--check] [--root DIR]
import { readFileSync, writeFileSync, readdirSync, unlinkSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const args = process.argv.slice(2);
const check = args.includes("--check");
const rootIdx = args.indexOf("--root");
const root = rootIdx >= 0
  ? resolve(args[rootIdx + 1])
  : resolve(dirname(fileURLToPath(import.meta.url)), "..");

const SECTIONS = ["Added", "Changed", "Fixed", "Security", "Removed", "Deprecated", "CI"];
const NAME = /^[a-z0-9][a-z0-9._-]*\.md$/;
const HEADING = new RegExp(`^### (${SECTIONS.join("|")})(\\s\\(.+\\))?\\s*$`);

const dir = join(root, "changelog.d");
const changelogPath = join(root, "CHANGELOG.md");
const fail = (msg) => { console.error(`changelog-fold: ${msg}`); process.exit(1); };

const files = readdirSync(dir)
  .filter((f) => f.endsWith(".md") && f !== "README.md")
  .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

const blocks = [];
for (const f of files) {
  if (!NAME.test(f)) fail(`${f}: bad file name (use <pr-or-slug>.md, lowercase)`);
  const text = readFileSync(join(dir, f), "utf8").replace(/\r\n/g, "\n").trim();
  if (!text) fail(`${f}: empty fragment`);
  const lines = text.split("\n");
  if (!HEADING.test(lines[0])) fail(`${f}: first line must be "### <${SECTIONS.join("|")}> (topic)"`);
  let bullets = 0;
  for (const l of lines) {
    if (l.startsWith("## ") || l.startsWith("# ")) fail(`${f}: only ### headings are allowed`);
    if (l.startsWith("### ") && !HEADING.test(l)) fail(`${f}: unknown section "${l}"`);
    if (/^\s*[-*] /.test(l)) bullets++;
  }
  if (bullets === 0) fail(`${f}: needs at least one bullet`);
  blocks.push(text);
}

const changelog = readFileSync(changelogPath, "utf8");
const marker = /^## \[Unreleased\][^\n]*\n/m;
const m = marker.exec(changelog);
if (!m) fail("CHANGELOG.md has no '## [Unreleased]' heading");

if (check || blocks.length === 0) {
  console.log(`changelog-fold: ${blocks.length} fragment(s) valid${check ? " (check only)" : ", nothing to fold"}`);
  process.exit(0);
}

const at = m.index + m[0].length;
const rest = changelog.slice(at).replace(/^\n+/, "");
const out = `${changelog.slice(0, at)}\n${blocks.join("\n\n")}\n\n${rest}`;
writeFileSync(changelogPath, out);
for (const f of files) unlinkSync(join(dir, f));
console.log(`changelog-fold: folded ${blocks.length} fragment(s): ${files.join(", ")}`);
