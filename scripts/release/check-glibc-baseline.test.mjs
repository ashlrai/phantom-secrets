import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

import {
  compareVersions,
  evaluateGlibcBaseline,
  parseGlibcRequirements,
  parseVersion,
} from "./check-glibc-baseline.mjs";

const repoRoot = resolve(import.meta.dirname, "../..");

const compatibleReadelf = `
Version needs section '.gnu.version_r' contains 1 entry:
 Addr: 0x0000000000001234  Offset: 0x001234  Link: 7 (.dynstr)
  000000: Version: 1  File: libc.so.6  Cnt: 3
  0x0010:   Name: GLIBC_2.2.5  Flags: none  Version: 4
  0x0020:   Name: GLIBC_2.17   Flags: none  Version: 3
  0x0030:   Name: GLIBC_2.34   Flags: none  Version: 2
`;

test("compares dotted GLIBC versions semantically", () => {
  assert.equal(compareVersions("2.2.5", "2.35"), -1);
  assert.equal(compareVersions("2.35", "2.35.0"), 0);
  assert.equal(compareVersions("2.36", "2.35"), 1);
  assert.deepEqual(parseVersion("2.2.5"), [2, 2, 5]);
  assert.throws(() => parseVersion("2.x"), /dotted numeric/);
});

test("parses, deduplicates, and orders numeric GLIBC requirements", () => {
  assert.deepEqual(parseGlibcRequirements(`${compatibleReadelf}\nGLIBC_2.17`), [
    "2.2.5",
    "2.17",
    "2.34",
  ]);
});

test("accepts requirements at or below the declared ceiling", () => {
  assert.deepEqual(evaluateGlibcBaseline(compatibleReadelf, "2.35"), {
    baseline: "2.35",
    highest: "2.34",
    required: ["2.2.5", "2.17", "2.34"],
  });
});

test("fails closed above the ceiling, for unknown requirements, or without evidence", () => {
  assert.throws(
    () => evaluateGlibcBaseline(`${compatibleReadelf}\nName: GLIBC_2.36`, "2.35"),
    /exceeds the GLIBC_2\.35 ceiling/,
  );
  assert.throws(
    () => evaluateGlibcBaseline("Name: GLIBC_PRIVATE", "2.35"),
    /unsupported GLIBC version requirement/,
  );
  assert.throws(
    () => evaluateGlibcBaseline("No version information found", "2.35"),
    /refusing a vacuous compatibility pass/,
  );
});

test("release and documentation contracts pin both GNU targets to the same gate", () => {
  const workflow = readFileSync(resolve(repoRoot, ".github/workflows/release.yml"), "utf8");
  const docs = readFileSync(resolve(repoRoot, "docs/platform-support.md"), "utf8");

  for (const target of ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"]) {
    const start = workflow.indexOf(`- target: ${target}`);
    assert.notEqual(start, -1, `missing release matrix row for ${target}`);
    const next = workflow.indexOf("\n          - target:", start + 1);
    const row = workflow.slice(start, next === -1 ? workflow.length : next);
    assert.match(row, /\n\s+os: ubuntu-22\.04\n/);
    assert.doesNotMatch(row, /ubuntu-latest/);
  }

  assert.match(workflow, /check-glibc-baseline\.mjs --baseline 2\.35/);
  assert.match(workflow, /target\/\$\{\{ matrix\.target \}\}\/release\/phantom(?:\s|$)/);
  assert.match(workflow, /target\/\$\{\{ matrix\.target \}\}\/release\/phantom-mcp(?:\s|$)/);
  assert.match(docs, /Ubuntu 22\.04/);
  assert.match(docs, /GLIBC_2\.35/);
  assert.match(docs, /does not constitute native runtime acceptance/i);
});
