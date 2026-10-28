#!/usr/bin/env node

import fs from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { compareVersions } from "./check-glibc-baseline.mjs";

const HEADING_LINE = /^## (.*)$/;
const BRACKETED_HEADING = /^\[([^\]]+)\](.*)$/;
const VERSION_LABEL = /^\d+\.\d+\.\d+$/;
const DATE_SUFFIX = /^ - (\d{4})-(\d{2})-(\d{2})$/;
const LINK_DEFINITION = /^\[([^\]]+)\]:\s*(\S+)\s*$/;
const COMPARE_URL = /^(\S+)\/compare\/v(\d+\.\d+\.\d+)\.\.\.(HEAD|v(\d+\.\d+\.\d+))$/;
const TAG_URL = /^(\S+)\/releases\/tag\/v(\d+\.\d+\.\d+)$/;

function isRealCalendarDate(year, month, day) {
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  return (
    date.getUTCFullYear() === year &&
    date.getUTCMonth() === month - 1 &&
    date.getUTCDate() === day
  );
}

function parseHeading(text, lineNumber, report) {
  if (text !== text.trim()) {
    report(lineNumber, "release heading must not have extra whitespace around it");
    return null;
  }
  const bracketed = text.match(BRACKETED_HEADING);
  if (!bracketed) {
    report(
      lineNumber,
      'level-2 heading must be "## [Unreleased]" or "## [X.Y.Z] - YYYY-MM-DD"'
    );
    return null;
  }
  const [, label, suffix] = bracketed;
  if (label === "Unreleased") {
    if (suffix !== "") {
      report(lineNumber, "## [Unreleased] must not carry a release date");
      return null;
    }
    return { lineNumber, label, kind: "unreleased" };
  }
  if (!VERSION_LABEL.test(label)) {
    report(
      lineNumber,
      `heading label [${label}] is not a semantic version; expected [X.Y.Z] or [Unreleased]`
    );
    return null;
  }
  if (suffix === "") {
    report(lineNumber, `version heading [${label}] is missing its " - YYYY-MM-DD" release date`);
    return null;
  }
  const date = suffix.match(DATE_SUFFIX);
  if (!date) {
    report(lineNumber, `version heading [${label}] must end with " - YYYY-MM-DD", found "${suffix}"`);
    return null;
  }
  const year = Number(date[1]);
  const month = Number(date[2]);
  const day = Number(date[3]);
  if (!isRealCalendarDate(year, month, day)) {
    report(lineNumber, `version heading [${label}] has impossible date${date[0]}`);
    return null;
  }
  return { lineNumber, label, kind: "version", version: label };
}

function checkLinkTarget(heading, versions, report) {
  const def = heading.def;
  const url = def.url;
  if (heading.kind === "unreleased") {
    const compare = url.match(COMPARE_URL);
    if (!compare || compare[3] !== "HEAD") {
      report(def.lineNumber, "[Unreleased] link must compare v<newest release>...HEAD");
      return;
    }
    if (versions.length > 0 && compare[2] !== versions[0].version) {
      report(
        def.lineNumber,
        `[Unreleased] link compares v${compare[2]}...HEAD; expected v${versions[0].version}...HEAD`
      );
    }
    return;
  }
  const index = versions.indexOf(heading);
  const older = versions[index + 1];
  const tag = url.match(TAG_URL);
  if (tag) {
    if (older) {
      report(
        def.lineNumber,
        `[${heading.label}] must compare v${older.version}...v${heading.label}; a tag link is only valid on the oldest listed release`
      );
      return;
    }
    if (tag[2] !== heading.label) {
      report(def.lineNumber, `[${heading.label}] tag link points at v${tag[2]}`);
    }
    return;
  }
  const compare = url.match(COMPARE_URL);
  if (!compare) {
    report(
      def.lineNumber,
      `[${heading.label}] link must be "<repo>/compare/v<older>...v${heading.label}"` +
        (older ? "" : " or \"<repo>/releases/tag/v" + heading.label + "\"")
    );
    return;
  }
  if (compare[3] === "HEAD") {
    report(def.lineNumber, `[${heading.label}] link compares against HEAD; only [Unreleased] may do that`);
    return;
  }
  if (compare[4] !== heading.label) {
    report(def.lineNumber, `[${heading.label}] link target is v${compare[4]}, not v${heading.label}`);
    return;
  }
  if (older && compare[2] !== older.version) {
    report(
      def.lineNumber,
      `[${heading.label}] link compares v${compare[2]}...v${heading.label}; expected v${older.version}...v${heading.label}`
    );
  }
}

export function lintChangelog(text, fileName = "CHANGELOG.md") {
  const issues = [];
  const report = (lineNumber, message) => issues.push({ line: lineNumber, message });
  const headings = [];
  const linkDefinitions = new Map();
  let openFence = null;
  let sawHeading = false;

  const lines = text.split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    const lineNumber = index + 1;
    const line = lines[index].replace(/\r$/, "");
    const fence = line.match(/^\s*(```|~~~)/);
    if (fence) {
      if (openFence === null) openFence = fence[1];
      else if (fence[1] === openFence) openFence = null;
      continue;
    }
    if (openFence !== null) continue;

    const heading = line.match(HEADING_LINE);
    if (heading) {
      sawHeading = true;
      const parsed = parseHeading(heading[1], lineNumber, report);
      if (parsed) headings.push(parsed);
      continue;
    }
    const link = line.match(LINK_DEFINITION);
    if (link) {
      const [, label, url] = link;
      const existing = linkDefinitions.get(label);
      if (existing) {
        report(lineNumber, `duplicate link definition [${label}] (first defined on line ${existing.lineNumber})`);
      } else {
        linkDefinitions.set(label, { lineNumber, url });
      }
    }
  }

  const unreleased = headings.filter((heading) => heading.kind === "unreleased");
  const versions = headings.filter((heading) => heading.kind === "version");
  if (!sawHeading) {
    report(1, `${fileName} has no "## [Unreleased]" or "## [X.Y.Z] - YYYY-MM-DD" headings`);
    return issues;
  }
  for (const heading of unreleased) {
    if (heading !== headings[0]) {
      report(heading.lineNumber, "## [Unreleased] must be the first level-2 heading");
    }
  }
  if (unreleased.length > 1) {
    report(unreleased[1].lineNumber, "duplicate ## [Unreleased] heading");
  }

  let previous = null;
  for (const heading of versions) {
    if (previous && compareVersions(heading.version, previous.version) >= 0) {
      const reason =
        compareVersions(heading.version, previous.version) === 0
          ? `duplicate version heading [${heading.label}]`
          : `version heading [${heading.label}] is out of order: headings must sort newest release first`;
      report(heading.lineNumber, reason);
    }
    previous = heading;
  }

  let repoBase = null;
  for (const heading of headings) {
    const def = linkDefinitions.get(heading.label);
    if (!def) {
      report(heading.lineNumber, `missing link definition "[${heading.label}]: <url>" for this heading`);
      continue;
    }
    heading.def = def;
    const base = (def.url.match(COMPARE_URL) ?? def.url.match(TAG_URL))?.[1];
    if (base) {
      if (repoBase === null) repoBase = base;
      else if (base !== repoBase) {
        report(def.lineNumber, `[${heading.label}] link uses ${base}; earlier links use ${repoBase}`);
      }
    }
  }
  for (const heading of headings) {
    if (heading.def) checkLinkTarget(heading, versions, report);
  }
  for (const [label, def] of linkDefinitions) {
    const referenced = label === "Unreleased" || VERSION_LABEL.test(label);
    if (referenced && !headings.some((heading) => heading.label === label)) {
      report(def.lineNumber, `link definition [${label}] has no matching heading`);
    }
  }

  issues.sort((left, right) => left.line - right.line);
  return issues;
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  const args = process.argv.slice(2);
  if (args.length > 1) {
    console.error("usage: lint-changelog.mjs [CHANGELOG_PATH]");
    process.exit(2);
  }
  const fileName = args[0] ?? "CHANGELOG.md";
  let text;
  try {
    text = fs.readFileSync(fileName, "utf8");
  } catch {
    console.error(`lint-changelog: cannot read ${fileName}`);
    process.exit(2);
  }
  const issues = lintChangelog(text, fileName);
  if (issues.length > 0) {
    for (const issue of issues) {
      console.error(`${fileName}:${issue.line}: ${issue.message}`);
    }
    console.error(`${fileName}: ${issues.length} changelog problem(s)`);
    process.exit(1);
  }
  console.log(`${fileName}: ok`);
}
