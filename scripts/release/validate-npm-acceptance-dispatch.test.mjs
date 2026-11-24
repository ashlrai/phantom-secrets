import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { formatGithubOutput, validateNpmAcceptanceDispatch } from "./validate-npm-acceptance-dispatch.mjs";

const script = fileURLToPath(new URL("./validate-npm-acceptance-dispatch.mjs", import.meta.url));
const sha = "a".repeat(40);
const primaryIntegrity = `sha512-${Buffer.alloc(64, 1).toString("base64")}`;
const mcpIntegrity = `sha512-${Buffer.alloc(64, 2).toString("base64")}`;

function input(overrides = {}) {
  return {
    repository: "ashlrai/phantom-secrets",
    ref: "refs/tags/v1.2.3",
    defaultBranch: "main",
    mode: "prepublication",
    version: "1.2.3",
    releaseSourceSha: sha,
    primaryIntegrity: "",
    mcpIntegrity: "",
    previousLatest: "1.2.2",
    previousCandidate: "1.2.1",
    ...overrides,
  };
}

test("prepublication on a release tag emits the seven canonical values and a derived tag", () => {
  const values = validateNpmAcceptanceDispatch(input());
  assert.deepEqual(values, {
    mode: "prepublication",
    version: "1.2.3",
    releaseSourceSha: sha,
    primaryIntegrity: "",
    mcpIntegrity: "",
    previousLatest: "1.2.2",
    previousCandidate: "1.2.1",
    releaseTag: "v1.2.3",
  });
  assert.equal(
    formatGithubOutput(values),
    [
      "mode=prepublication",
      "version=1.2.3",
      `release_source_sha=${sha}`,
      "primary_integrity=",
      "mcp_integrity=",
      "previous_latest=1.2.2",
      "previous_candidate=1.2.1",
      "release_tag=v1.2.3",
      "",
    ].join("\n"),
  );
});

test("published-candidate accepts only canonical sha512 integrities", () => {
  const values = validateNpmAcceptanceDispatch(input({
    mode: "published-candidate",
    primaryIntegrity,
    mcpIntegrity,
  }));
  assert.equal(values.mode, "published-candidate");
  assert.equal(values.primaryIntegrity, primaryIntegrity);
  assert.equal(values.mcpIntegrity, mcpIntegrity);
  assert.throws(
    () => validateNpmAcceptanceDispatch(input({ mode: "published-candidate" })),
    /requires both approved sha512 integrity values/,
  );
  assert.throws(
    () => validateNpmAcceptanceDispatch(input({ primaryIntegrity })),
    /rejects public integrity inputs/,
  );
});

test("the default branch is protected and every other ref fails closed", () => {
  assert.equal(validateNpmAcceptanceDispatch(input({ ref: "refs/heads/main" })).version, "1.2.3");
  assert.throws(
    () => validateNpmAcceptanceDispatch(input({ ref: "refs/heads/main", defaultBranch: "develop" })),
    /not the default branch or a release tag/,
  );
  for (const ref of ["refs/heads/feature", "refs/tags/v1.2.4", "refs/tags/vfoo", "refs/tags/v1.2.3-rc.1"]) {
    assert.throws(() => validateNpmAcceptanceDispatch(input({ ref })), /release tag|format check/);
  }
});

test("format checks reject free-form values and omit them from the error", () => {
  const sentinel = "INJECTED_VALUE_SHOULD_NOT_LEAK";
  const cases = [
    [{ mode: `${sentinel}` }, /mode failed format check/],
    [{ version: `1.2.3\n${sentinel}` }, /version failed format check/],
    [{ version: "01.2.3" }, /version failed format check/],
    [{ version: "1.2.3-rc.1" }, /version failed format check/],
    [{ releaseSourceSha: "A".repeat(40) }, /release_source_sha failed format check/],
    [{ releaseSourceSha: `${sha}${sentinel}` }, /release_source_sha failed format check/],
    [{ previousLatest: "1.2.3" }, /previous_latest must differ/],
    [{ previousCandidate: "1.2.3" }, /previous_candidate must differ/],
    [{ primaryIntegrity: `sha512-${sentinel}` }, /primary_integrity failed format check/],
    [{ repository: sentinel }, /restricted to ashlrai\/phantom-secrets/],
    [{ defaultBranch: `../${sentinel}` }, /default branch failed format check/],
  ];
  for (const [overrides, expectation] of cases) {
    assert.throws(() => validateNpmAcceptanceDispatch(input(overrides)), (error) => {
      assert.match(error.message, expectation);
      assert.equal(error.message.includes(sentinel), false);
      return true;
    });
  }
  const wide = "9".repeat(21);
  assert.equal(validateNpmAcceptanceDispatch(input({
    ref: "refs/heads/main",
    version: `${wide}.0.0`,
    previousLatest: "0.1.0",
    previousCandidate: "0.2.0",
  })).version, `${wide}.0.0`);
  assert.throws(
    () => validateNpmAcceptanceDispatch(input({ version: `${"9".repeat(65)}.0.0`, ref: "refs/heads/main" })),
    /version failed format check/,
  );
});

test("cli appends canonical output and writes nothing when validation fails", () => {
  const dir = mkdtempSync(join(tmpdir(), "npm-acceptance-dispatch-"));
  try {
    const output = join(dir, "github-output");
    writeFileSync(output, "");
    const env = {
      PATH: process.env.PATH,
      GITHUB_OUTPUT: output,
      GITHUB_REPOSITORY: "ashlrai/phantom-secrets",
      ACCEPTANCE_REF: "refs/tags/v1.2.3",
      ACCEPTANCE_DEFAULT_BRANCH: "main",
      RAW_MODE: "prepublication",
      RAW_VERSION: "1.2.3",
      RAW_RELEASE_SOURCE_SHA: sha,
      RAW_PRIMARY_INTEGRITY: "",
      RAW_MCP_INTEGRITY: "",
      RAW_PREVIOUS_LATEST: "1.2.2",
      RAW_PREVIOUS_CANDIDATE: "1.2.1",
    };
    const ok = spawnSync(process.execPath, [script], { encoding: "utf8", env });
    assert.equal(ok.status, 0, ok.stderr);
    assert.match(readFileSync(output, "utf8"), /^mode=prepublication\n/);
    writeFileSync(output, "prior\n");
    const sentinel = "INJECTED_VALUE_SHOULD_NOT_LEAK";
    const bad = spawnSync(process.execPath, [script], {
      encoding: "utf8",
      env: { ...env, RAW_VERSION: sentinel },
    });
    assert.notEqual(bad.status, 0);
    assert.equal(readFileSync(output, "utf8"), "prior\n");
    assert.match(bad.stderr, /version failed format check/);
    assert.equal(bad.stderr.includes(sentinel), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
