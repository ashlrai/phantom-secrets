#!/usr/bin/env node

import fs from "node:fs";

const tag = process.argv[2];
if (!/^v\d+\.\d+\.\d+$/.test(tag ?? "")) {
  console.error("usage: extract-release-notes.mjs vMAJOR.MINOR.PATCH");
  process.exit(2);
}

const version = tag.slice(1);
const changelog = fs.readFileSync("CHANGELOG.md", "utf8");
const heading = `## [${version}]`;
const start = changelog.indexOf(heading);
if (start === -1) {
  console.error(`CHANGELOG.md has no ${heading} section`);
  process.exit(1);
}

const next = changelog.indexOf("\n## [", start + heading.length);
const section = changelog.slice(start, next === -1 ? undefined : next).trim();
if (!section.includes("### Breaking changes and migration")) {
  console.error(`${heading} has no breaking-change migration section`);
  process.exit(1);
}

process.stdout.write(`${section}\n`);
