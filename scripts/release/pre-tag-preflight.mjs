#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const tagPattern =
  /^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
const shaPattern = /^[0-9a-f]{40}$/i;
const canonicalRunUrlPattern =
  /^https:\/\/github\.com\/([^/]+)\/([^/]+)\/actions\/runs\/([1-9][0-9]*)\/?$/;
const expectedNativeTargets = [
  "aarch64-apple-darwin",
  "aarch64-pc-windows-msvc",
  "aarch64-unknown-linux-gnu",
  "x86_64-apple-darwin",
  "x86_64-pc-windows-msvc",
  "x86_64-unknown-linux-gnu",
];
const npmPackages = ["phantom-secrets", "phantom-secrets-mcp"];
const npmRegistry = "https://registry.npmjs.org/";
const minimumNpmVersion = [11, 15, 0];

function defaultCommandRunner(file, args, options = {}) {
  const result = spawnSync(file, args, {
    cwd: options.cwd,
    encoding: "utf8",
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 60_000,
    maxBuffer: 4 * 1024 * 1024,
  });
  if (result.error) {
    throw result.error;
  }
  return {
    status: result.status ?? 1,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

function run(commandRunner, file, args, cwd, label, allowedStatuses = [0]) {
  let result;
  try {
    result = commandRunner(file, args, { cwd });
  } catch {
    throw new Error(`${label} is unavailable`);
  }
  const status = Number.isInteger(result?.status) ? result.status : 1;
  if (!allowedStatuses.includes(status)) {
    // Deliberately omit subprocess stderr. Authentication helpers and remote
    // implementations are not trusted to keep credential material out of it.
    throw new Error(`${label} failed with status ${status}`);
  }
  return { status, stdout: String(result.stdout ?? "") };
}

function parseJson(output, label) {
  try {
    return JSON.parse(output);
  } catch {
    throw new Error(`${label} returned malformed JSON`);
  }
}

function parseStableVersion(value, label) {
  const match = String(value ?? "")
    .trim()
    .match(/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/);
  if (!match) {
    throw new Error(`${label} returned a non-stable semantic version`);
  }
  return match.slice(1).map(Number);
}

function versionAtLeast(actual, minimum) {
  for (let index = 0; index < minimum.length; index += 1) {
    if (actual[index] > minimum[index]) return true;
    if (actual[index] < minimum[index]) return false;
  }
  return true;
}

function verifyGithubReleaseAbsent(commandRunner, cwd, repository, tag) {
  const result = run(
    commandRunner,
    "gh",
    ["api", "--include", `repos/${repository}/releases/tags/${tag}`],
    cwd,
    "GitHub release reservation lookup",
    [0, 1],
  );
  if (result.status === 0) {
    throw new Error(`GitHub release ${tag} already exists`);
  }
  if (!/^HTTP\/(?:1\.\d|2(?:\.0)?) 404(?: Not Found)?\r?$/m.test(result.stdout)) {
    throw new Error("GitHub release absence could not be proven");
  }
}

function verifyNpmReservationsAbsent(commandRunner, cwd, version) {
  const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
  const npmVersion = parseStableVersion(
    run(commandRunner, npmCommand, ["--version"], cwd, "npm CLI version lookup")
      .stdout,
    "npm CLI version lookup",
  );
  if (!versionAtLeast(npmVersion, minimumNpmVersion)) {
    throw new Error(
      `npm >=${minimumNpmVersion.join(".")} is required for stage reservation checks`,
    );
  }

  for (const name of npmPackages) {
    const versions = parseJson(
      run(
        commandRunner,
        npmCommand,
        ["view", name, "versions", "--json", `--registry=${npmRegistry}`],
        cwd,
        `${name} public version lookup`,
      ).stdout,
      `${name} public version lookup`,
    );
    const published = Array.isArray(versions) ? versions : [versions];
    if (published.includes(version)) {
      throw new Error(`${name}@${version} is already public`);
    }

    const stages = parseJson(
      run(
        commandRunner,
        npmCommand,
        [
          "stage",
          "list",
          name,
          "--json",
          `--registry=${npmRegistry}`,
        ],
        cwd,
        `${name} npm stage reservation lookup`,
      ).stdout,
      `${name} npm stage reservation lookup`,
    );
    if (!Array.isArray(stages)) {
      throw new Error(
        `${name} npm stage reservation lookup returned a non-array response`,
      );
    }
    if (
      stages.some(
        (stage) =>
          !stage ||
          typeof stage !== "object" ||
          stage.packageName !== name ||
          typeof stage.version !== "string" ||
          stage.version.length === 0,
      )
    ) {
      throw new Error(
        `${name} npm stage reservation lookup returned a malformed stage record`,
      );
    }
    if (stages.some((stage) => stage?.version === version)) {
      throw new Error(`${name}@${version} already has an npm stage reservation`);
    }
  }

  return {
    cli_minimum: minimumNpmVersion.join("."),
    registry: npmRegistry,
    packages: [...npmPackages],
    exact_version_public: false,
    exact_version_staged: false,
  };
}

function normalizeRunInput(runInput, repository) {
  if (/^[1-9][0-9]*$/.test(runInput ?? "")) {
    return runInput;
  }
  const match = String(runInput ?? "").match(canonicalRunUrlPattern);
  if (!match) {
    throw new Error(
      "release rehearsal must be a positive run ID or canonical github.com Actions run URL",
    );
  }
  if (`${match[1]}/${match[2]}`.toLowerCase() !== repository.toLowerCase()) {
    throw new Error("release rehearsal URL belongs to a different repository");
  }
  return match[3];
}

function canonicalJobName(name) {
  return String(name ?? "").split(" / ").at(-1);
}

function verifyRehearsal(run, runId, repository, headSha) {
  if (String(run.databaseId) !== runId) {
    throw new Error("release rehearsal response does not match the requested run ID");
  }
  if (run.workflowName !== "Release rehearsal" || run.event !== "workflow_dispatch") {
    throw new Error("run is not the manual Release rehearsal workflow");
  }
  if (run.status !== "completed" || run.conclusion !== "success") {
    throw new Error("release rehearsal is not completed successfully");
  }
  if (String(run.headSha ?? "").toLowerCase() !== headSha) {
    throw new Error("release rehearsal head SHA does not match the candidate");
  }
  const runUrl = String(run.url ?? "");
  const parsedUrl = runUrl.match(canonicalRunUrlPattern);
  if (
    !parsedUrl ||
    `${parsedUrl[1]}/${parsedUrl[2]}`.toLowerCase() !== repository.toLowerCase() ||
    parsedUrl[3] !== runId
  ) {
    throw new Error("release rehearsal returned a non-canonical or mismatched URL");
  }
  if (!Array.isArray(run.jobs) || run.jobs.length === 0) {
    throw new Error("release rehearsal has no inspectable jobs");
  }
  const unsuccessful = run.jobs.filter(
    (job) => job.status !== "completed" || job.conclusion !== "success",
  );
  if (unsuccessful.length > 0) {
    throw new Error("release rehearsal contains non-successful jobs");
  }

  const canonicalNames = run.jobs.map((job) => canonicalJobName(job.name));
  const sourceJobs = canonicalNames.filter(
    (name) => name === "Verify source and release contract",
  );
  if (sourceJobs.length !== 1) {
    throw new Error(
      "release rehearsal does not contain exactly one source-verification job",
    );
  }

  const buildTargets = canonicalNames
    .map((name) => name.match(/^Build \(([^)]+)\)$/)?.[1])
    .filter(Boolean)
    .sort();
  if (
    buildTargets.length !== expectedNativeTargets.length ||
    buildTargets.some((target, index) => target !== expectedNativeTargets[index])
  ) {
    throw new Error("release rehearsal does not contain the exact six build jobs");
  }

  const nativeTargets = canonicalNames
    .map((name) => name.match(/^Native acceptance \(([^)]+)\)$/)?.[1])
    .filter(Boolean)
    .sort();
  if (
    nativeTargets.length !== expectedNativeTargets.length ||
    nativeTargets.some((target, index) => target !== expectedNativeTargets[index])
  ) {
    throw new Error("release rehearsal does not contain the exact six native acceptance jobs");
  }
  const bundleJobs = canonicalNames.filter(
    (name) => name === "Verify checksums, artifacts, and SBOMs",
  );
  if (bundleJobs.length !== 1) {
    throw new Error("release rehearsal does not contain exactly one verified-bundle job");
  }
  const expectedTotalJobs = 2 + expectedNativeTargets.length * 2;
  if (run.jobs.length !== expectedTotalJobs) {
    throw new Error("release rehearsal does not contain the exact 14-job graph");
  }
  return { runUrl, buildTargets, nativeTargets, totalJobs: run.jobs.length };
}

function refPatternMatches(pattern, tagRef) {
  if (pattern === "~ALL") {
    return true;
  }
  const candidate = pattern.startsWith("refs/")
    ? tagRef
    : tagRef.replace(/^refs\/tags\//, "");
  const expression = String(pattern)
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "\0")
    .replace(/\*/g, "[^/]*")
    .replace(/\0/g, ".*")
    .replace(/\?/g, "[^/]");
  return new RegExp(`^${expression}$`).test(candidate);
}

function refConditionCoversReleaseTag(ruleset, tag) {
  if (ruleset.target !== "tag" || ruleset.enforcement !== "active") {
    return false;
  }
  const tagRef = `refs/tags/${tag}`;
  const condition = ruleset.conditions?.ref_name;
  const include = condition?.include;
  const exclude = condition?.exclude;
  return Boolean(
    Array.isArray(include) &&
      include.some((pattern) => refPatternMatches(pattern, tagRef)) &&
      (!Array.isArray(exclude) ||
        !exclude.some((pattern) => refPatternMatches(pattern, tagRef))),
  );
}

function verifyGovernance(environment, policies, rulesets, tag) {
  const reviewers = environment.protection_rules?.find(
    (rule) => rule.type === "required_reviewers",
  )?.reviewers;
  if (!Array.isArray(reviewers) || reviewers.length === 0) {
    throw new Error("release environment has no required reviewer");
  }
  if (environment.deployment_branch_policy?.custom_branch_policies !== true) {
    throw new Error("release environment does not require custom deployment policies");
  }
  const deploymentPolicies = policies.branch_policies;
  if (
    !Array.isArray(deploymentPolicies) ||
    !deploymentPolicies.some(
      (policy) => policy.type === "tag" && ["v*", "refs/tags/v*"].includes(policy.name),
    )
  ) {
    throw new Error("release environment has no v-prefixed tag deployment policy");
  }

  const applicable = rulesets.filter((ruleset) =>
    refConditionCoversReleaseTag(ruleset, tag),
  );
  const creationRulesets = applicable.filter((ruleset) =>
    ruleset.rules?.some((rule) => rule.type === "creation"),
  );
  if (creationRulesets.length === 0) {
    throw new Error("no active ruleset restricts v-prefixed tag creation");
  }
  if (!creationRulesets.some((ruleset) => ruleset.bypass_actors?.length > 0)) {
    throw new Error("tag creation is restricted but has no explicit bypass actor");
  }
  const immutableRulesets = applicable.filter((ruleset) => {
    const types = new Set((ruleset.rules ?? []).map((rule) => rule.type));
    return (
      (ruleset.bypass_actors?.length ?? 0) === 0 &&
      ["update", "deletion", "non_fast_forward"].every((type) => types.has(type))
    );
  });
  if (immutableRulesets.length === 0) {
    throw new Error(
      "no no-bypass ruleset prevents v-prefixed tag update, deletion, and non-fast-forward changes",
    );
  }
  return {
    requiredReviewerCount: reviewers.length,
    creationRulesetIds: creationRulesets.map((ruleset) => ruleset.id).sort(),
    immutableRulesetIds: immutableRulesets.map((ruleset) => ruleset.id).sort(),
  };
}

function repositoryFromOrigin(originUrl) {
  const value = String(originUrl ?? "").trim();
  const match = value.match(
    /^(?:https:\/\/github\.com\/|git@github\.com:|ssh:\/\/git@github\.com\/)([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/,
  );
  if (!match) {
    throw new Error("origin is not a canonical github.com repository URL");
  }
  return `${match[1]}/${match[2]}`;
}

function readRepository(commandRunner, cwd) {
  const originRepository = repositoryFromOrigin(
    run(
      commandRunner,
      "git",
      ["remote", "get-url", "origin"],
      cwd,
      "origin repository lookup",
    ).stdout,
  );
  const output = run(
    commandRunner,
    "gh",
    ["repo", "view", originRepository, "--json", "nameWithOwner"],
    cwd,
    "GitHub repository lookup",
  ).stdout;
  const repository = parseJson(output, "GitHub repository lookup").nameWithOwner;
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository ?? "")) {
    throw new Error("GitHub repository lookup returned an invalid repository name");
  }
  if (repository.toLowerCase() !== originRepository.toLowerCase()) {
    throw new Error("GitHub repository lookup does not match origin");
  }
  return repository;
}

function refreshCandidate(commandRunner, cwd, tag) {
  const headSha = run(
    commandRunner,
    "git",
    ["rev-parse", "--verify", "HEAD^{commit}"],
    cwd,
    "candidate HEAD lookup",
  ).stdout.trim().toLowerCase();
  const remoteMain = run(
    commandRunner,
    "git",
    ["ls-remote", "--heads", "origin", "refs/heads/main"],
    cwd,
    "remote main lookup",
  ).stdout.trim();
  const remoteMainMatch = remoteMain.match(
    /^([0-9a-f]{40})\trefs\/heads\/main$/i,
  );
  if (!shaPattern.test(headSha) || !remoteMainMatch) {
    throw new Error("candidate or remote main SHA is malformed");
  }
  const mainSha = remoteMainMatch[1].toLowerCase();
  if (headSha !== mainSha) {
    throw new Error("candidate HEAD is not the current remote main commit");
  }
  const status = run(
    commandRunner,
    "git",
    ["status", "--porcelain=v1", "--untracked-files=all"],
    cwd,
    "candidate cleanliness check",
  ).stdout;
  if (status !== "") {
    throw new Error("candidate worktree is not exactly clean");
  }

  const tagRef = `refs/tags/${tag}`;
  const localTag = run(
    commandRunner,
    "git",
    ["show-ref", "--verify", "--quiet", tagRef],
    cwd,
    "local tag lookup",
    [0, 1],
  );
  if (localTag.status === 0) {
    throw new Error(`release tag ${tag} already exists locally`);
  }
  const remoteTags = run(
    commandRunner,
    "git",
    ["ls-remote", "--tags", "origin", tagRef, `${tagRef}^{}`],
    cwd,
    "remote tag lookup",
  ).stdout.trim();
  if (remoteTags !== "") {
    throw new Error(`release tag ${tag} already exists remotely`);
  }
  return headSha;
}

export function runPreTagPreflight({
  tag,
  runInput,
  cwd = repoRoot,
  commandRunner = defaultCommandRunner,
} = {}) {
  if (!tagPattern.test(tag ?? "") || !runInput) {
    throw new Error(
      "usage: pre-tag-preflight.mjs vMAJOR.MINOR.PATCH REHEARSAL_RUN_ID_OR_URL",
    );
  }

  const initialSha = refreshCandidate(commandRunner, cwd, tag);
  run(
    commandRunner,
    process.execPath,
    [resolve(cwd, "scripts/release/check-version-parity.mjs"), tag],
    cwd,
    "release version parity check",
  );
  run(
    commandRunner,
    process.execPath,
    [resolve(cwd, "scripts/release/extract-release-notes.mjs"), tag],
    cwd,
    "release note check",
  );

  const repository = readRepository(commandRunner, cwd);
  const runId = normalizeRunInput(runInput, repository);
  const runData = parseJson(
    run(
      commandRunner,
      "gh",
      [
        "run",
        "view",
        runId,
        "--repo",
        repository,
        "--json",
        "databaseId,url,workflowName,event,headSha,status,conclusion,jobs",
      ],
      cwd,
      "release rehearsal lookup",
    ).stdout,
    "release rehearsal lookup",
  );
  const rehearsal = verifyRehearsal(runData, runId, repository, initialSha);

  const environment = parseJson(
    run(
      commandRunner,
      "gh",
      ["api", `repos/${repository}/environments/release`],
      cwd,
      "release environment governance lookup",
    ).stdout,
    "release environment governance lookup",
  );
  const policies = parseJson(
    run(
      commandRunner,
      "gh",
      ["api", `repos/${repository}/environments/release/deployment-branch-policies`],
      cwd,
      "release deployment policy lookup",
    ).stdout,
    "release deployment policy lookup",
  );
  const ruleSummaries = parseJson(
    run(
      commandRunner,
      "gh",
      ["api", `repos/${repository}/rulesets?includes_parents=true`],
      cwd,
      "release ruleset lookup",
    ).stdout,
    "release ruleset lookup",
  );
  if (!Array.isArray(ruleSummaries) || ruleSummaries.length === 0) {
    throw new Error("release ruleset lookup returned no rulesets");
  }
  const rulesets = ruleSummaries.map((summary) => {
    if (!Number.isInteger(summary.id) || summary.id <= 0) {
      throw new Error("release ruleset lookup returned an invalid ruleset ID");
    }
    return parseJson(
      run(
        commandRunner,
        "gh",
        ["api", `repos/${repository}/rulesets/${summary.id}`],
        cwd,
        `release ruleset ${summary.id} lookup`,
      ).stdout,
      `release ruleset ${summary.id} lookup`,
    );
  });
  const governance = verifyGovernance(environment, policies, rulesets, tag);

  // A draft release or npm stage can reserve an otherwise absent version.
  // Prove those external identities are still unclaimed before emitting the
  // irreversible annotated-tag commands.
  verifyGithubReleaseAbsent(commandRunner, cwd, repository, tag);
  const npmReservations = verifyNpmReservationsAbsent(
    commandRunner,
    cwd,
    tag.slice(1),
  );

  // Close the race between the earlier source checks and external governance
  // and reservation inspection. No commands are printed unless the candidate
  // is still exact.
  const finalSha = refreshCandidate(commandRunner, cwd, tag);
  if (finalSha !== initialSha) {
    throw new Error("candidate changed during pre-tag preflight");
  }

  const receipt = {
    schema_version: 1,
    kind: "phantom_pre_tag_preflight",
    result: "pass",
    release_tag: tag,
    repository,
    source_sha: finalSha,
    origin_main_sha: finalSha,
    rehearsal: {
      run_id: runId,
      url: rehearsal.runUrl,
      workflow: "Release rehearsal",
      event: "workflow_dispatch",
      conclusion: "success",
      total_successful_jobs: rehearsal.totalJobs,
      build_targets: rehearsal.buildTargets,
      native_acceptance_targets: rehearsal.nativeTargets,
      verified_bundle_jobs: 1,
    },
    governance: {
      release_environment: "release",
      required_reviewer_count: governance.requiredReviewerCount,
      v_tag_policy: true,
      creation_ruleset_ids: governance.creationRulesetIds,
      immutable_ruleset_ids: governance.immutableRulesetIds,
    },
    reservations: {
      github_release_absent: true,
      npm: npmReservations,
    },
    credential_values_emitted: false,
    mutations_performed: [],
  };
  const commands = [
    `git tag -a '${tag}' '${finalSha}' -m 'Phantom ${tag}'`,
    `git push origin 'refs/tags/${tag}'`,
  ];
  return { receipt, commands };
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  if (process.argv.length !== 4) {
    console.error(
      "usage: pre-tag-preflight.mjs vMAJOR.MINOR.PATCH REHEARSAL_RUN_ID_OR_URL",
    );
    process.exit(2);
  }
  try {
    const result = runPreTagPreflight({ tag: process.argv[2], runInput: process.argv[3] });
    console.log(JSON.stringify(result.receipt, null, 2));
    console.log("\nPreflight passed. These commands were not executed:");
    for (const command of result.commands) {
      console.log(command);
    }
  } catch (error) {
    console.error(`pre-tag preflight blocked: ${error.message}`);
    process.exit(1);
  }
}
