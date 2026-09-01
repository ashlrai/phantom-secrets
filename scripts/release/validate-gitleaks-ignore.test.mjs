import assert from "node:assert/strict";
import test from "node:test";

import { validateGitleaksIgnore } from "./validate-gitleaks-ignore.mjs";

const candidateReachable = "a".repeat(40);
const originReachable = "b".repeat(40);
const unreachable = "c".repeat(40);

test("accepts an empty approved-history exception set", () => {
  assert.equal(validateGitleaksIgnore("# reviewed\n", () => true), 0);
});

test("accepts sorted unique fingerprints from the candidate or canonical origin heads", () => {
  const policy = [
    `${candidateReachable}:path/to/candidate:generic-api-key:7`,
    `${originReachable}:path/to/origin:private-key:1`,
  ].join("\n");
  assert.equal(
    validateGitleaksIgnore(
      `${policy}\n`,
      (commit) => commit === candidateReachable || commit === originReachable,
    ),
    2,
  );
});

test("rejects malformed, duplicate, and unsorted fingerprints", () => {
  assert.throws(
    () => validateGitleaksIgnore("not-a-fingerprint\n", () => true),
    /Malformed/,
  );
  const exact = `${candidateReachable}:a:rule:1`;
  assert.throws(
    () => validateGitleaksIgnore(`${exact}\n${exact}\n`, () => true),
    /unique/,
  );
  assert.throws(
    () =>
      validateGitleaksIgnore(
        `${candidateReachable}:z:rule:1\n${candidateReachable}:a:rule:1\n`,
        () => true,
      ),
    /sorted/,
  );
});

test("rejects an unknown or unreachable commit", () => {
  const policy = `${unreachable}:path/to/file:private-key:1\n`;
  assert.throws(
    () => validateGitleaksIgnore(policy, (commit) => commit === candidateReachable),
    /not reachable/,
  );
});
