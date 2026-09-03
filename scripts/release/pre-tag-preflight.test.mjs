import assert from "node:assert/strict";
import { test } from "node:test";

import { runPreTagPreflight } from "./pre-tag-preflight.mjs";

const sha = "a".repeat(40);
const repository = "ashlrai/phantom-secrets";
const runId = "123456789";
const runUrl = `https://github.com/${repository}/actions/runs/${runId}`;
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
const nativeTargets = [
  "x86_64-apple-darwin",
  "aarch64-apple-darwin",
  "x86_64-unknown-linux-gnu",
  "aarch64-unknown-linux-gnu",
  "x86_64-pc-windows-msvc",
  "aarch64-pc-windows-msvc",
];

function success(stdout = "") {
  return { status: 0, stdout, stderr: "" };
}

function successfulRun(overrides = {}) {
  return {
    databaseId: Number(runId),
    url: runUrl,
    workflowName: "Release rehearsal",
    event: "workflow_dispatch",
    headSha: sha,
    status: "completed",
    conclusion: "success",
    jobs: [
      { name: "Build and natively verify release artifacts / Verify source and release contract" },
      ...nativeTargets.map((target) => ({
        name: `Build and natively verify release artifacts / Build (${target})`,
      })),
      ...nativeTargets.map((target) => ({
        name: `Build and natively verify release artifacts / Native acceptance (${target})`,
      })),
      { name: "Build and natively verify release artifacts / Verify checksums, artifacts, and SBOMs" },
    ].map((job) => ({ ...job, status: "completed", conclusion: "success" })),
    ...overrides,
  };
}

function environment() {
  return {
    protection_rules: [
      {
        type: "required_reviewers",
        reviewers: [{ type: "User", reviewer: { login: "release-reviewer" } }],
      },
    ],
    deployment_branch_policy: {
      protected_branches: false,
      custom_branch_policies: true,
    },
  };
}

function ruleset(id, rules, bypassActors = []) {
  return {
    id,
    target: "tag",
    enforcement: "active",
    bypass_actors: bypassActors,
    conditions: { ref_name: { include: ["refs/tags/v*"], exclude: [] } },
    rules: rules.map((type) => ({ type })),
  };
}

function createRunner({
  headSha = sha,
  mainSha = sha,
  status = "",
  localTagStatus = 1,
  remoteTags = "",
  runData = successfulRun(),
  environmentData = environment(),
  policyData = { branch_policies: [{ name: "v*", type: "tag" }] },
  rulesets = [
    ruleset(11, ["creation"], [{ actor_id: 1, actor_type: "RepositoryRole" }]),
    ruleset(12, ["update", "deletion", "non_fast_forward"]),
  ],
  originUrl = `https://github.com/${repository}.git`,
  repositoryData = repository,
  githubReleaseLookup = {
    status: 1,
    stdout: "HTTP/2.0 404 Not Found\n\n{}\n",
    stderr: "gh: Not Found (HTTP 404)\n",
  },
  npmVersion = "11.15.0",
  npmPublishedVersions = [],
  npmStages = {},
} = {}) {
  const calls = [];
  const runner = (file, args) => {
    calls.push({ file, args: [...args] });
    if (file === "git" && args.join(" ") === "rev-parse --verify HEAD^{commit}") {
      return success(`${headSha}\n`);
    }
    if (file === "git" && args.join(" ") === "remote get-url origin") {
      return success(`${originUrl}\n`);
    }
    if (
      file === "git" &&
      args.join(" ") === "ls-remote --heads origin refs/heads/main"
    ) {
      return success(`${mainSha}\trefs/heads/main\n`);
    }
    if (file === "git" && args[0] === "status") return success(status);
    if (file === "git" && args[0] === "show-ref") {
      return { status: localTagStatus, stdout: "", stderr: "" };
    }
    if (file === "git" && args[0] === "ls-remote") return success(remoteTags);
    if (file === process.execPath && args[0].endsWith("check-version-parity.mjs")) {
      return success("parity passed\n");
    }
    if (file === process.execPath && args[0].endsWith("extract-release-notes.mjs")) {
      return success("release notes\n");
    }
    if (file === "gh" && args[0] === "repo") {
      return success(JSON.stringify({ nameWithOwner: repositoryData }));
    }
    if (file === "gh" && args[0] === "run") return success(JSON.stringify(runData));
    if (file === "gh" && args[0] === "api") {
      const endpoint = args[1];
      if (endpoint === "--include") {
        assert.equal(
          args[2],
          `repos/${repository}/releases/tags/v0.7.6`,
        );
        return githubReleaseLookup;
      }
      if (endpoint.endsWith("/environments/release")) {
        return success(JSON.stringify(environmentData));
      }
      if (endpoint.endsWith("/environments/release/deployment-branch-policies")) {
        return success(JSON.stringify(policyData));
      }
      if (endpoint.endsWith("/rulesets?includes_parents=true")) {
        return success(JSON.stringify(rulesets.map(({ id }) => ({ id }))));
      }
      const id = Number(endpoint.match(/\/rulesets\/(\d+)$/)?.[1]);
      const found = rulesets.find((candidate) => candidate.id === id);
      if (found) return success(JSON.stringify(found));
    }
    if (file === npmCommand && args.join(" ") === "--version") {
      return success(`${npmVersion}\n`);
    }
    if (file === npmCommand && args[0] === "view") {
      assert.deepEqual(args.slice(2), [
        "versions",
        "--json",
        "--registry=https://registry.npmjs.org/",
      ]);
      const versions = npmPublishedVersions[args[1]] ?? npmPublishedVersions;
      return success(JSON.stringify(versions));
    }
    if (file === npmCommand && args[0] === "stage") {
      assert.equal(args[1], "list");
      assert.ok(!args[2].includes("@"));
      assert.deepEqual(args.slice(3), [
        "--json",
        "--registry=https://registry.npmjs.org/",
      ]);
      return success(JSON.stringify(npmStages[args[2]] ?? []));
    }
    assert.fail(`unexpected command: ${file} ${args.join(" ")}`);
  };
  return { runner, calls };
}

test("passes only after source, rehearsal, governance, and reservation gates", () => {
  const { runner, calls } = createRunner();
  const result = runPreTagPreflight({
    tag: "v0.7.6",
    runInput: runUrl,
    cwd: "/fixture/repo",
    commandRunner: runner,
  });

  assert.equal(result.receipt.result, "pass");
  assert.equal(result.receipt.source_sha, sha);
  assert.equal(result.receipt.rehearsal.run_id, runId);
  assert.deepEqual(result.receipt.rehearsal.build_targets, [
    "aarch64-apple-darwin",
    "aarch64-pc-windows-msvc",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-linux-gnu",
  ]);
  assert.deepEqual(result.receipt.rehearsal.native_acceptance_targets, [
    "aarch64-apple-darwin",
    "aarch64-pc-windows-msvc",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-linux-gnu",
  ]);
  assert.deepEqual(result.receipt.mutations_performed, []);
  assert.deepEqual(result.receipt.reservations, {
    github_release_absent: true,
    npm: {
      cli_minimum: "11.15.0",
      registry: "https://registry.npmjs.org/",
      packages: ["phantom-secrets", "phantom-secrets-mcp"],
      exact_version_public: false,
      exact_version_staged: false,
    },
  });
  assert.deepEqual(result.commands, [
    `git tag -a 'v0.7.6' '${sha}' -m 'Phantom v0.7.6'`,
    "git push origin 'refs/tags/v0.7.6'",
  ]);
  assert.equal(
    calls.filter(({ file, args }) => file === "git" && args[0] === "fetch")
      .length,
    0,
  );
  assert.equal(
    calls.filter(({ file, args }) => file === "git" && args[0] === "ls-remote")
      .length,
    4,
  );
  assert.equal(
    calls.filter(({ file, args }) => file === npmCommand && args[0] === "stage")
      .length,
    2,
  );
  assert.equal(calls.some(({ args }) => args.includes("tag") || args.includes("push")), false);
});

test("fails closed on existing or unprovable GitHub release reservations", () => {
  for (const [githubReleaseLookup, message] of [
    [success('{"tag_name":"v0.7.6"}'), /GitHub release v0\.7\.6 already exists/],
    [
      {
        status: 1,
        stdout: "HTTP/2.0 500 Internal Server Error\n",
        stderr: "secret",
      },
      /GitHub release absence could not be proven/,
    ],
  ]) {
    const { runner } = createRunner({ githubReleaseLookup });
    assert.throws(
      () =>
        runPreTagPreflight({
          tag: "v0.7.6",
          runInput: runId,
          cwd: "/fixture/repo",
          commandRunner: runner,
        }),
      message,
    );
  }
});

test("fails closed on unsupported npm, public versions, and stage reservations", () => {
  const cases = [
    {
      npmVersion: "11.14.9",
      message: /npm >=11\.15\.0 is required/,
    },
    {
      npmPublishedVersions: {
        "phantom-secrets": ["0.6.0", "0.7.6"],
        "phantom-secrets-mcp": ["0.6.0"],
      },
      message: /phantom-secrets@0\.7\.6 is already public/,
    },
    {
      npmStages: {
        "phantom-secrets": [
          { id: "reserved-stage", packageName: "phantom-secrets", version: "0.7.6" },
        ],
      },
      message: /phantom-secrets@0\.7\.6 already has an npm stage reservation/,
    },
    {
      npmStages: {
        "phantom-secrets": {},
      },
      message: /non-array response/,
    },
    {
      npmStages: {
        "phantom-secrets": [{ id: "missing-version", packageName: "phantom-secrets" }],
      },
      message: /malformed stage record/,
    },
  ];

  for (const { message, ...options } of cases) {
    const { runner } = createRunner(options);
    assert.throws(
      () =>
        runPreTagPreflight({
          tag: "v0.7.6",
          runInput: runId,
          cwd: "/fixture/repo",
          commandRunner: runner,
        }),
      message,
    );
  }
});

test("lists npm stages by package and ignores reservations for other versions", () => {
  const { runner, calls } = createRunner({
    npmStages: {
      "phantom-secrets": [
        { id: "older-stage", packageName: "phantom-secrets", version: "0.7.4" },
      ],
      "phantom-secrets-mcp": [
        {
          id: "older-mcp-stage",
          packageName: "phantom-secrets-mcp",
          version: "0.7.4",
        },
      ],
    },
  });

  const result = runPreTagPreflight({
    tag: "v0.7.6",
    runInput: runId,
    cwd: "/fixture/repo",
    commandRunner: runner,
  });

  assert.equal(result.receipt.reservations.npm.exact_version_staged, false);
  assert.deepEqual(
    calls
      .filter(({ file, args }) => file === npmCommand && args[0] === "stage")
      .map(({ args }) => args.slice(0, 3)),
    [
      ["stage", "list", "phantom-secrets"],
      ["stage", "list", "phantom-secrets-mcp"],
    ],
  );
});

test("accepts a positive run ID directly", () => {
  const { runner } = createRunner();
  assert.equal(
    runPreTagPreflight({
      tag: "v0.7.6",
      runInput: runId,
      cwd: "/fixture/repo",
      commandRunner: runner,
    }).receipt.rehearsal.url,
    runUrl,
  );
});

test("rejects malformed tags and cross-repository run URLs before emitting commands", () => {
  const { runner } = createRunner();
  assert.throws(
    () =>
      runPreTagPreflight({
        tag: "v01.7.4",
        runInput: runId,
        cwd: "/fixture/repo",
        commandRunner: runner,
      }),
    /usage:/,
  );
  assert.throws(
    () =>
      runPreTagPreflight({
        tag: "v0.7.6",
        runInput: `https://github.com/other/project/actions/runs/${runId}`,
        cwd: "/fixture/repo",
        commandRunner: runner,
      }),
    /different repository/,
  );
});

test("binds GitHub governance to the canonical origin repository", () => {
  for (const [options, message] of [
    [
      { originUrl: "https://example.com/ashlrai/phantom-secrets.git" },
      /origin is not a canonical github\.com repository URL/,
    ],
    [
      { repositoryData: "other/project" },
      /GitHub repository lookup does not match origin/,
    ],
  ]) {
    const { runner } = createRunner(options);
    assert.throws(
      () =>
        runPreTagPreflight({
          tag: "v0.7.6",
          runInput: runId,
          cwd: "/fixture/repo",
          commandRunner: runner,
        }),
      message,
    );
  }
});

test("fails closed on dirty source, stale main, and existing tags", () => {
  for (const [options, message] of [
    [{ status: "?? untracked.txt\n" }, /not exactly clean/],
    [{ mainSha: "b".repeat(40) }, /not the current remote main/],
    [{ localTagStatus: 0 }, /already exists locally/],
    [{ remoteTags: `${"b".repeat(40)}\trefs\/tags\/v0.7.6\n` }, /already exists remotely/],
  ]) {
    const { runner } = createRunner(options);
    assert.throws(
      () =>
        runPreTagPreflight({
          tag: "v0.7.6",
          runInput: runId,
          cwd: "/fixture/repo",
          commandRunner: runner,
        }),
      message,
    );
  }
});

test("requires the exact successful candidate rehearsal and all native jobs", () => {
  for (const [runData, message] of [
    [successfulRun({ headSha: "b".repeat(40) }), /head SHA/],
    [successfulRun({ conclusion: "failure" }), /not completed successfully/],
    [
      successfulRun({ jobs: successfulRun().jobs.slice(1) }),
      /exactly one source-verification job/,
    ],
    [
      successfulRun({
        jobs: successfulRun().jobs.filter(
          (job) => !job.name.endsWith("Build (aarch64-apple-darwin)"),
        ),
      }),
      /exact six build jobs/,
    ],
    [
      successfulRun({
        jobs: [
          ...successfulRun().jobs,
          successfulRun().jobs.find((job) =>
            job.name.endsWith("Build (aarch64-apple-darwin)"),
          ),
        ],
      }),
      /exact six build jobs/,
    ],
    [
      successfulRun({ jobs: successfulRun().jobs.slice(0, -2) }),
      /exact six native acceptance jobs/,
    ],
    [
      successfulRun({ jobs: successfulRun().jobs.slice(0, -1) }),
      /exactly one verified-bundle job/,
    ],
    [
      successfulRun({
        jobs: successfulRun().jobs.map((job, index) =>
          index === 1 ? { ...job, conclusion: "failure" } : job,
        ),
      }),
      /non-successful jobs/,
    ],
  ]) {
    const { runner } = createRunner({ runData });
    assert.throws(
      () =>
        runPreTagPreflight({
          tag: "v0.7.6",
          runInput: runId,
          cwd: "/fixture/repo",
          commandRunner: runner,
        }),
      message,
    );
  }
});

test("blocks when required external governance cannot be proven", () => {
  const cases = [
    {
      environmentData: { ...environment(), protection_rules: [] },
      message: /no required reviewer/,
    },
    {
      policyData: { branch_policies: [] },
      message: /no v-prefixed tag deployment policy/,
    },
    {
      rulesets: [ruleset(12, ["update", "deletion", "non_fast_forward"])],
      message: /no active ruleset restricts.*creation/,
    },
    {
      rulesets: [
        {
          ...ruleset(11, ["creation"], [{ actor_id: 1 }]),
          conditions: {
            ref_name: {
              include: ["refs/tags/v*"],
              exclude: ["refs/tags/v0.7.6"],
            },
          },
        },
        ruleset(12, ["update", "deletion", "non_fast_forward"]),
      ],
      message: /no active ruleset restricts.*creation/,
    },
    {
      rulesets: [
        ruleset(11, ["creation"], [{ actor_id: 1 }]),
        {
          ...ruleset(12, ["update", "deletion", "non_fast_forward"]),
          conditions: {
            ref_name: {
              include: ["refs/tags/v*"],
              exclude: ["v0.7.*"],
            },
          },
        },
      ],
      message: /no no-bypass ruleset/,
    },
    {
      rulesets: [
        ruleset(11, ["creation"], [{ actor_id: 1 }]),
        ruleset(12, ["update", "deletion"]),
      ],
      message: /no no-bypass ruleset/,
    },
  ];
  for (const { message, ...options } of cases) {
    const { runner } = createRunner(options);
    assert.throws(
      () =>
        runPreTagPreflight({
          tag: "v0.7.6",
          runInput: runId,
          cwd: "/fixture/repo",
          commandRunner: runner,
        }),
      message,
    );
  }
});

test("does not include subprocess stderr in a blocker", () => {
  const runner = () => ({
    status: 1,
    stdout: "",
    stderr: "authorization: secret-bearing-helper-output",
  });
  assert.throws(
    () =>
      runPreTagPreflight({
        tag: "v0.7.6",
        runInput: runId,
        cwd: "/fixture/repo",
        commandRunner: runner,
      }),
    (error) => {
      assert.match(error.message, /candidate HEAD lookup failed/);
      assert.doesNotMatch(error.message, /secret-bearing/);
      return true;
    },
  );
});
