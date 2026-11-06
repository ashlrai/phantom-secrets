/** Exact manual-full evidence for the existing immutable Secrets release. */
import { createHash } from 'node:crypto';
import { appendFileSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const REPO = 'ashlrai/phantom-secrets';
export const REPOSITORY_ID = 1194099157;
export const CI_WORKFLOW_ID = 252681774;
export const RELEASE_WORKFLOW_ID = 252681777;
export const POLICY_FILES = [
  '.github/workflows/ci.yml', '.github/workflows/release.yml', '.github/workflows/release-build.yml',
  '.github/workflows/auto-tag.yml', 'scripts/release/qualify-full-ci.mjs',
  'scripts/release/verify-github-tag-binding.mjs', 'scripts/release/verify-release-artifacts.mjs',
  'scripts/release/verify-github-release-receipt.mjs', 'scripts/release/compare-release-artifacts.mjs',
  'scripts/release/extract-release-notes.mjs',
];
export const REQUIRED_JOBS = [
  'Classify changes', 'Test (macos-latest)', 'Test (ubuntu-latest)', 'Test (windows-latest)',
  'Ignored Tests (macos-latest)', 'Ignored Tests (ubuntu-latest)', 'Ignored Tests (windows-latest)',
  'Lint', 'Rust dependency policy', 'Windows ARM64 source check', 'npm wrapper tests and package inspection',
  'Web security, tests, and build', 'Source secret scan', 'Secret-shape scan', 'Crate publication contract',
  'Temporal codec example tests', 'CI Gate', 'Upload coverage', 'Daily fixup queue',
];
const COMMON_TEST = ['Build', 'Verify examples', 'Verify installed CLI and MCP onboarding',
  'Verify platform and installer mappings', 'Verify MCP platform mappings'];
export const CRITICAL_STEPS = {
  'Test (macos-latest)': [...COMMON_TEST, 'Run tests', 'Check installer shell syntax'],
  'Test (windows-latest)': [...COMMON_TEST, 'Run tests', 'Parse candidate and public-reference PowerShell installers',
    'Exercise the Windows installer with the existing debug binaries'],
  'Test (ubuntu-latest)': [...COMMON_TEST, 'Install coverage tools', 'Install cargo-llvm-cov',
    'Run tests with coverage', 'Upload coverage report', 'Run pq-hybrid feature tests',
    'Verify MCP registry catalog matches runtime tools/list', 'Check installer shell syntax',
    'Install zsh for installer startup tests', 'Run direct installer offline tests',
    'Run isolated alias fallback shell test', 'Run isolated LC_ALL preservation shell test',
    'Run isolated LC_CTYPE preservation shell test', 'Run isolated LANG preservation shell test',
    'Run isolated TZ preservation shell test', 'Run isolated COLUMNS preservation shell test',
    'Run isolated spaced-parent staging shell test', 'Run isolated staging-failure shell test'],
  'Ignored Tests (macos-latest)': ['Run ignored tests (real OS keychain)'],
  'Ignored Tests (ubuntu-latest)': ['Run ignored tests (real OS keychain)'],
  'Ignored Tests (windows-latest)': ['Run ignored tests (real OS keychain)'],
  'Lint': ['Check formatting', 'Clippy', 'Check installer shell syntax'],
  'Rust dependency policy': ['Reject tracked dependency installations', 'Install verified cargo-deny',
    'Check advisories, licenses, bans, duplicates, and sources'],
  'Windows ARM64 source check': ['Verify native host and check the workspace'],
  'npm wrapper tests and package inspection': ['Test and inspect primary CLI wrapper on Node 22',
    'Test and inspect MCP wrapper on Node 22', 'Test primary CLI wrapper on Node 24', 'Test MCP wrapper on Node 24'],
  'Web security, tests, and build': ['Verify immutable migration source contract', 'Install from the lockfile',
    'Install the exact npm audit CLI', 'Audit production dependencies', 'Lint web source',
    'Run web security and auth tests', 'Verify credential-free SEO observation contract',
    'Build the production application', 'Install pinned Supabase CLI', 'Confirm exact Supabase CLI version',
    'Start isolated local database', 'Replay every migration from an empty local database',
    'Verify local migration history', 'Assert local database authority boundaries', 'Lint local schema',
    'Run local security and performance advisors', 'Tear down local database and delete its volumes'],
  'Source secret scan': ['Fetch canonical origin heads for history policy', 'Install pinned Gitleaks',
    'Scan current source with the reviewed fixture policy', 'Validate exact candidate and canonical-origin history policy',
    'Scan candidate and canonical origin ancestry against reviewed fingerprints'],
  'Secret-shape scan': ['Scan candidate diff (fail closed)'],
  'Crate publication contract': ['Test fail-closed publication and release receipts',
    'Install checksum-verified MCP Registry publisher', 'Validate the staged MCP Registry manifest',
    'Package every crates.io crate in dependency order'],
  'Temporal codec example tests': ['Install pinned dependencies', 'Run codec, CORS and key delivery tests'],
  'CI Gate': ['Require every selected job'],
  // Codecov retains its existing soft external-upload policy; this is not an
  // assertion of extra tests beyond the successful Linux coverage producer.
  'Upload coverage': ['Download coverage report', 'Require the coverage file', 'Upload coverage to Codecov'],
  'Daily fixup queue': ['Checkout scrubber', 'Build fixup-queue.txt', 'Upload fixup queue'],
};
const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const SHA = /^[a-f0-9]{40}$/;
const HASH = /^[a-f0-9]{64}$/;
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
function require(value, reason) { if (!value) throw new Error(reason); }
function integer(value) { require(Number.isSafeInteger(value) && value > 0, 'invalid-evidence-integer'); return value; }
function tagVersion(tag) {
  require(typeof tag === 'string' && tag.length <= 128 && /^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(tag), 'invalid-release-tag');
  return tag.slice(1);
}
function list(doc, key) {
  require(Number.isSafeInteger(doc.total_count) && doc.total_count <= 100 && Array.isArray(doc[key]) &&
    doc[key].length === doc.total_count, 'incomplete-evidence-inventory');
  return doc[key];
}
export function releaseEnvironment(env, mode) {
  tagVersion(env.RELEASE_TAG);
  const ref = `refs/tags/${env.RELEASE_TAG}`;
  require(env.GITHUB_REPOSITORY === REPO && env.GITHUB_EVENT_NAME === 'push' && env.GITHUB_REF === ref &&
    env.GITHUB_WORKFLOW_REF === `${REPO}/.github/workflows/release.yml@${ref}` && SHA.test(env.GITHUB_SHA ?? ''), 'untrusted-release-invocation');
  if (mode === 'qualify') require(!env.ACTIONS_ID_TOKEN_REQUEST_TOKEN && !env.ACTIONS_ID_TOKEN_REQUEST_URL, 'qualifier-must-have-no-oidc');
  return { tag: env.RELEASE_TAG, policySha: env.GITHUB_SHA };
}
export function matchesRun(run, source, tag) {
  return run?.repository?.id === REPOSITORY_ID && run.repository.full_name === REPO &&
    run.head_repository?.id === REPOSITORY_ID && run.head_repository.full_name === REPO &&
    run.workflow_id === CI_WORKFLOW_ID && run.path === '.github/workflows/ci.yml' && run.event === 'workflow_dispatch' &&
    run.head_sha === source && run.head_branch === tag;
}
export function validateVersions(tag, manifests) {
  const version = tagVersion(tag), names = ['phantom-secrets', 'phantom-secrets-mcp'];
  require(Array.isArray(manifests) && manifests.length === names.length && manifests.every((manifest, i) =>
    manifest?.name === names[i] && manifest.version === version), 'candidate-package-version-mismatch');
}
export function validateRun(run, source, tag, id, attempt, completed = false) {
  integer(id); integer(attempt);
  require(['queued', 'requested', 'pending', 'waiting', 'in_progress', 'completed'].includes(run?.status), 'unknown-ci-run-status');
  require(matchesRun(run, source, tag) && run.id === id && run.run_attempt === attempt, 'ci-run-or-attempt-binding-changed');
  if (completed) require(run.status === 'completed' && run.conclusion === 'success', 'canonical-full-ci-not-successful');
  else if (run.status === 'completed') require(run.conclusion === 'success', 'canonical-full-ci-failed');
}
export function validateJobs(doc, runId, attempt) {
  const jobs = list(doc, 'jobs'), expected = [...REQUIRED_JOBS, 'Docs command check'];
  require(jobs.length === expected.length && new Set(jobs.map(job => job.id)).size === jobs.length, 'ci-job-inventory-drift');
  for (const name of expected) {
    const found = jobs.filter(job => job.name === name); require(found.length === 1, 'ci-job-missing-or-duplicated');
    const job = found[0]; integer(job.id);
    require(job.run_id === runId && job.run_attempt === attempt && job.status === 'completed' &&
      job.conclusion === (name === 'Docs command check' ? 'skipped' : 'success'), 'ci-job-incomplete-failed-or-mixed-attempt');
    for (const name of CRITICAL_STEPS[job.name] ?? []) {
      const steps = job.steps?.filter(step => step.name === name);
      require(steps?.length === 1 && steps[0].status === 'completed' && steps[0].conclusion === 'success', 'required-full-step-did-not-succeed');
    }
  }
  return jobs.map(({ id, name }) => ({ id, name }));
}
export function validatePolicy(input, evidence, localHashes) {
  const { repo, branch, rules, ciWorkflow, releaseWorkflow, ancestry, files } = evidence;
  require(repo.id === REPOSITORY_ID && repo.full_name === REPO && repo.default_branch === 'main' &&
    branch.protected === true && SHA.test(branch.commit?.sha ?? ''), 'canonical-main-protection-missing');
  require(Array.isArray(rules) && rules.some(rule => rule.type === 'required_status_checks' &&
    rule.parameters?.required_status_checks?.some(check => check.context === 'CI Gate' && check.integration_id === 15368)), 'canonical-required-gate-missing');
  require(ciWorkflow.id === CI_WORKFLOW_ID && ciWorkflow.path === '.github/workflows/ci.yml' && ciWorkflow.state === 'active' &&
    releaseWorkflow.id === RELEASE_WORKFLOW_ID && releaseWorkflow.path === '.github/workflows/release.yml' && releaseWorkflow.state === 'active', 'canonical-workflow-changed-or-disabled');
  for (const sha of new Set([input.source, input.policySha])) {
    require(SHA.test(sha) && ['ahead', 'identical'].includes(ancestry[sha]?.status) &&
      ancestry[sha]?.merge_base_commit?.sha === sha, 'source-or-policy-not-canonical-ancestor');
  }
  require(Object.keys(files).length === POLICY_FILES.length && Object.keys(localHashes).length === POLICY_FILES.length, 'policy-closure-inventory-drift');
  for (const path of POLICY_FILES) require(HASH.test(localHashes[path] ?? '') && files[path]?.length === 3 &&
    files[path].every(value => value === localHashes[path]), 'source-or-current-policy-changed');
}
async function bounded(response) {
  const limit = 8 * 1024 * 1024;
  require(Number(response.headers.get('content-length') ?? 0) <= limit && response.body, 'bounded-response-unavailable');
  const reader = response.body.getReader(), chunks = []; let bytes = 0;
  try { for (;;) { const next = await reader.read(); if (next.done) break; bytes += next.value.byteLength;
    require(bytes <= limit, 'bounded-response-exceeded'); chunks.push(next.value); } }
  finally { try { await reader.cancel(); } finally { reader.releaseLock(); } }
  return Buffer.concat(chunks, bytes);
}
export async function githubJson(path, options = {}) {
  let response;
  try { response = await fetch(`https://api.github.com/repos/${REPO}${path ? `/${path}` : ''}`, {
    method: options.method ?? 'GET', redirect: 'error', signal: AbortSignal.timeout(15_000),
    headers: { Authorization: `Bearer ${process.env.GH_TOKEN ?? process.env.GITHUB_TOKEN ?? ''}`,
      Accept: 'application/vnd.github+json', 'Content-Type': 'application/json' },
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  }); } catch { throw new Error('github-evidence-unavailable'); }
  require(response.status === (options.method === 'POST' ? 204 : 200), 'github-evidence-unavailable');
  if (response.status === 204) return undefined;
  try { return JSON.parse((await bounded(response)).toString('utf8')); }
  catch { throw new Error('github-json-evidence-unavailable'); }
}
export async function resolveAnnotatedTag(tag, api) {
  tagVersion(tag);
  const ref = await api(`git/ref/tags/${tag}`);
  require(ref.ref === `refs/tags/${tag}` && ref.object?.type === 'tag' && SHA.test(ref.object.sha), 'release-tag-not-annotated');
  const object = await api(`git/tags/${ref.object.sha}`);
  require(object.tag === tag && object.object?.type === 'commit' && SHA.test(object.object.sha), 'release-tag-not-exact-commit');
  return object.object.sha;
}
async function policy(input, api, hashes) {
  const [repo, branch, rules, ciWorkflow, releaseWorkflow] = await Promise.all([
    api(''), api('branches/main'), api('rules/branches/main'), api('actions/workflows/ci.yml'), api('actions/workflows/release.yml'),
  ]);
  require(SHA.test(branch.commit?.sha ?? ''), 'invalid-current-main');
  const commits = [input.source, input.policySha, branch.commit.sha], unique = [...new Set(commits)];
  const ancestry = Object.fromEntries(await Promise.all([...new Set(commits.slice(0, 2))].map(async sha =>
    [sha, await api(`compare/${sha}...${branch.commit.sha}`)])));
  const files = Object.fromEntries(await Promise.all(POLICY_FILES.map(async path => {
    const values = Object.fromEntries(await Promise.all(unique.map(async sha => {
      const file = await api(`contents/${path}?ref=${sha}`);
      require(file.type === 'file' && file.path === path && file.encoding === 'base64' && file.size <= 1024 * 1024, 'invalid-policy-file');
      return [sha, hash(Buffer.from(file.content, 'base64'))];
    })));
    return [path, commits.map(sha => values[sha])];
  })));
  validatePolicy(input, { repo, branch, rules, ciWorkflow, releaseWorkflow, ancestry, files }, hashes);
}
export async function runGate(mode, env, deps = {}) {
  require(['qualify', 'verify'].includes(mode), 'invalid-qualification-mode');
  const input = releaseEnvironment(env, mode), api = deps.api ?? githubJson;
  const hashes = deps.hashes ?? Object.fromEntries(POLICY_FILES.map(path => [path, hash(readFileSync(resolve(ROOT, path)))]));
  const now = deps.now ?? Date.now, sleep = deps.sleep ?? (ms => new Promise(resolve => setTimeout(resolve, ms)));
  input.source = await resolveAnnotatedTag(input.tag, api);
  require(input.source === input.policySha, 'pushed-tag-source-changed');
  const manifests = await Promise.all(['npm/package.json', 'npm-mcp/package.json'].map(async path => {
    const file = await api(`contents/${path}?ref=${input.source}`);
    require(file.type === 'file' && file.path === path && file.encoding === 'base64' && file.size <= 64 * 1024, 'invalid-package-manifest');
    try { return JSON.parse(Buffer.from(file.content, 'base64').toString('utf8')); }
    catch { throw new Error('invalid-package-manifest'); }
  }));
  validateVersions(input.tag, manifests);
  await policy(input, api, hashes);
  const exactProducers = async () => {
    const runs = list(await api(`actions/workflows/${CI_WORKFLOW_ID}/runs?event=workflow_dispatch&head_sha=${input.source}&per_page=100`), 'workflow_runs');
    require(runs.every(run => Number.isSafeInteger(run.id) && run.id > 0) && new Set(runs.map(run => run.id)).size === runs.length, 'ambiguous-run-inventory');
    return runs.filter(run => matchesRun(run, input.source, input.tag)).sort((a, b) => b.id - a.id);
  };
  let runId, attempt;
  if (mode === 'verify') {
    runId = Number(env.FULL_CI_RUN_ID); attempt = Number(env.FULL_CI_ATTEMPT);
    require(env.FULL_CI_SOURCE === input.source, 'qualified-tag-source-moved');
  } else {
    let found = (await exactProducers())[0];
    if (!found) {
      // GitHub's monotonic release attempt survives job restarts. A retried
      // qualifier may reuse visible evidence, but never replay an uncertain
      // dispatch whose response/evidence was lost by the original attempt.
      require(env.GITHUB_RUN_ATTEMPT === '1', 'retried-release-dispatch-unresolved-no-resend');
      // A single dispatch attempt; lost responses reconcile by reads only.
      try { await api(`actions/workflows/${CI_WORKFLOW_ID}/dispatches`, { method: 'POST', body: { ref: input.tag } }); }
      catch { /* uncertain response: poll, never resend */ }
      const deadline = now() + 120_000;
      while (!found && now() < deadline) { await sleep(5_000); found = (await exactProducers())[0]; }
      require(found, 'canonical-ci-dispatch-unresolved-no-resend');
    }
    runId = integer(found.id); attempt = integer(found.run_attempt);
    const deadline = now() + 45 * 60_000;
    for (;;) {
      const run = await api(`actions/runs/${runId}`); validateRun(run, input.source, input.tag, runId, attempt);
      if (run.status === 'completed') break;
      require(now() < deadline, 'canonical-full-ci-deadline'); await sleep(15_000);
    }
  }
  integer(runId); integer(attempt);
  validateRun(await api(`actions/runs/${runId}`), input.source, input.tag, runId, attempt, true);
  const jobs = validateJobs(await api(`actions/runs/${runId}/attempts/${attempt}/jobs?per_page=100`), runId, attempt);
  // Live policy/attempt checks remain outside the frozen evidence tuple. The
  // existing stricter main==C tag-binding guard is deliberately unchanged.
  await policy(input, api, hashes);
  require(await resolveAnnotatedTag(input.tag, api) === input.source, 'tag-source-changed');
  validateRun(await api(`actions/runs/${runId}`), input.source, input.tag, runId, attempt, true);
  // Re-list on every verification: a later exact producer must never be hidden
  // behind this older frozen tuple, even if the later run is also successful.
  const latest = (await exactProducers())[0];
  require(latest?.id === runId && latest.run_attempt === attempt, 'latest-exact-producer-changed');
  return { schema: 'phantom-secrets.manual-full-ci.v1', tag: input.tag, source: input.source, runId, attempt, jobs };
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const result = await runGate(process.argv[2], process.env);
    if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT,
      `full_ci_run_id=${result.runId}\nfull_ci_attempt=${result.attempt}\nsource_sha=${result.source}\n`);
    console.log(`Qualified exact manual full CI ${result.runId} attempt ${result.attempt} for ${result.tag}`);
  } catch (error) { console.error(`Full CI qualification refused: ${error.message}`); process.exitCode = 1; }
}
