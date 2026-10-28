import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const here = dirname(fileURLToPath(import.meta.url));
const checker = resolve(here, "check-agent-secrets-plan.mjs");
const { checkPlan, checkSpec, extractSpec } = await import(checker);

function fixture(run) {
  const root = mkdtempSync(join(tmpdir(), "phantom-jobspec-test-"));
  try {
    return run(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function validJob(overrides = {}) {
  return {
    id: "RQ-PS-TEST-ONE",
    title: "job one",
    covers: ["create"],
    role: "core",
    status: "proposed",
    depends_on: [],
    scope: "does a thing",
    acceptance: ["works"],
    tests: ["a test exists"],
    ...overrides,
  };
}

function validSpec(jobs) {
  return {
    schemaVersion: 1,
    epic: "RQ-PLAN-SECRETS",
    requiredCoverage: ["create", "get", "use", "github_api_route"],
    coverVocabulary: ["create", "get", "use", "github_api_route"],
    jobs,
  };
}

const fourLegs = [
  validJob(),
  validJob({ id: "RQ-PS-TEST-TWO", covers: ["get"] }),
  validJob({ id: "RQ-PS-TEST-THREE", covers: ["use"] }),
  validJob({ id: "RQ-PS-TEST-FOUR", covers: ["github_api_route"] }),
];

test("the real plan document is well-formed and its claims hold", () => {
  assert.deepEqual(checkPlan(), []);
});

test("checker CLI passes on the real plan", () => {
  const result = spawnSync(process.execPath, [checker], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /PASS:/);
});

test("extractSpec requires exactly one jobspec block", () => {
  assert.match(extractSpec("no block here").errors[0], /no .*phantom-jobspec block/);
  const two = "```json phantom-jobspec\n{}\n```\n```json phantom-jobspec\n{}\n```";
  assert.match(extractSpec(two).errors[0], /exactly one/);
  assert.match(extractSpec("```json phantom-jobspec\n{bad}\n```").errors[0], /not valid JSON/);
  const ok = extractSpec("```json phantom-jobspec\n{\"schemaVersion\":1}\n```");
  assert.deepEqual(ok.errors, []);
  assert.equal(ok.spec.schemaVersion, 1);
});

test("complete spec passes", () =>
  fixture((root) => {
    assert.deepEqual(checkSpec(validSpec(fourLegs), root), []);
  }));

test("duplicate ids, unknown deps and cycles are caught", () =>
  fixture((root) => {
    const dup = checkSpec(validSpec([...fourLegs, validJob()]), root);
    assert.ok(dup.some((error) => /duplicate job id/.test(error)));

    const missingDep = validSpec(fourLegs.map((job) =>
      job.id === "RQ-PS-TEST-TWO" ? { ...job, depends_on: ["RQ-PS-NOPE"] } : job));
    assert.ok(checkSpec(missingDep, root).some((error) => /unknown job RQ-PS-NOPE/.test(error)));

    const cyclic = validSpec(fourLegs.map((job) => {
      if (job.id === "RQ-PS-TEST-ONE") return { ...job, depends_on: ["RQ-PS-TEST-TWO"] };
      if (job.id === "RQ-PS-TEST-TWO") return { ...job, depends_on: ["RQ-PS-TEST-ONE"] };
      return job;
    }));
    assert.ok(checkSpec(cyclic, root).some((error) => /dependency cycle/.test(error)));
  }));

test("uncovered epic legs and unknown cover tags fail", () =>
  fixture((root) => {
    const uncovered = checkSpec(validSpec([validJob()]), root);
    for (const tag of ["get", "use", "github_api_route"]) {
      assert.ok(uncovered.some((error) => error.includes(`"${tag}"`)), tag);
    }
    const badTag = validSpec(fourLegs.map((job) =>
      job.id === "RQ-PS-TEST-ONE" ? { ...job, covers: ["create", "bogus"] } : job));
    assert.ok(checkSpec(badTag, root).some((error) => /unknown covers tag "bogus"/.test(error)));
  }));

test("jobs must carry scope, acceptance, tests and a valid status", () =>
  fixture((root) => {
    const bare = validSpec(fourLegs.map((job) =>
      job.id === "RQ-PS-TEST-ONE"
        ? { id: job.id, covers: job.covers, depends_on: [] }
        : job));
    const errors = checkSpec(bare, root);
    for (const pattern of [/missing title/, /missing scope/, /role must be/, /status must be/, /acceptance must be a non-empty array/, /tests must be a non-empty array/]) {
      assert.ok(errors.some((error) => pattern.test(error)), pattern);
    }
    const dispatched = validSpec(fourLegs.map((job) =>
      job.id === "RQ-PS-TEST-ONE" ? { ...job, status: "dispatched" } : job));
    assert.ok(checkSpec(dispatched, root).some((error) => /must name its branch/.test(error)));
  }));

test("claims pin real file state and surfaces.modified must exist", () =>
  fixture((root) => {
    mkdirSync(join(root, "docs"), { recursive: true });
    writeFileSync(join(root, "docs", "route.md"), "github_api lives here");

    const good = validSpec(fourLegs.map((job) =>
      job.id === "RQ-PS-TEST-ONE"
        ? {
            ...job,
            surfaces: { new: ["docs/planned.md"], modified: ["docs/route.md"] },
            claims: [
              { expect: "present", path: "docs/route.md", contains: "github_api" },
              { expect: "absent", "path": "docs/planned.md" },
            ],
          }
        : job));
    assert.deepEqual(checkSpec(good, root), []);

    const stale = validSpec(fourLegs.map((job) =>
      job.id === "RQ-PS-TEST-ONE"
        ? {
            ...job,
            surfaces: { new: [], modified: ["docs/missing.md"] },
            claims: [
              { expect: "present", path: "docs/route.md", contains: "wrong text" },
              { expect: "present", path: "docs/missing.md" },
              { expect: "absent", path: "docs/route.md" },
            ],
          }
        : job));
    const errors = checkSpec(stale, root);
    for (const pattern of [/surfaces\.modified path does not exist: docs\/missing\.md/, /does not contain "wrong text"/, /expected file to exist/, /expected absent but file exists/]) {
      assert.ok(errors.some((error) => pattern.test(error)), pattern);
    }
  }));
