import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { CI_WORKFLOW_ID, CRITICAL_STEPS, githubJson, POLICY_FILES, REQUIRED_JOBS, REPO, REPOSITORY_ID,
  RELEASE_WORKFLOW_ID, releaseEnvironment, resolveAnnotatedTag, runGate, validateJobs, validatePolicy,
  validateRun, validateVersions } from './qualify-full-ci.mjs';

const C = 'a'.repeat(40), P = 'b'.repeat(40), MAIN = 'c'.repeat(40), TAG_OBJECT = 'd'.repeat(40);
const TAG = 'v0.8.5', RUN = 101, ATTEMPT = 2;
const digest = value => createHash('sha256').update(value).digest('hex');
const bytes = 'synthetic reviewed policy\n';
const hashes = Object.fromEntries(POLICY_FILES.map(path => [path, digest(bytes)]));
const env = { GITHUB_REPOSITORY: REPO, GITHUB_EVENT_NAME: 'push', GITHUB_REF: `refs/tags/${TAG}`,
  GITHUB_WORKFLOW_REF: `${REPO}/.github/workflows/release.yml@refs/tags/${TAG}`, GITHUB_SHA: C,
  RELEASE_TAG: TAG, GITHUB_RUN_ATTEMPT: '1', FULL_CI_RUN_ID: String(RUN), FULL_CI_ATTEMPT: String(ATTEMPT), FULL_CI_SOURCE: C };
function run() { return { id: RUN, run_attempt: ATTEMPT, repository: { id: REPOSITORY_ID, full_name: REPO },
  head_repository: { id: REPOSITORY_ID, full_name: REPO }, workflow_id: CI_WORKFLOW_ID,
  path: '.github/workflows/ci.yml', event: 'workflow_dispatch', head_sha: C, head_branch: TAG,
  status: 'completed', conclusion: 'success' }; }
function jobs() {
  const names = [...REQUIRED_JOBS, 'Docs command check'];
  return { total_count: 20, jobs: names.map((name, i) => ({ id: 201 + i, name, run_id: RUN, run_attempt: ATTEMPT,
    status: 'completed', conclusion: name === 'Docs command check' ? 'skipped' : 'success',
    steps: (CRITICAL_STEPS[name] ?? []).map(name => ({ name, status: 'completed', conclusion: 'success' })) })) };
}
function policyEvidence() { return {
  repo: { id: REPOSITORY_ID, full_name: REPO, default_branch: 'main' },
  branch: { protected: true, commit: { sha: MAIN } },
  rules: [{ type: 'required_status_checks', parameters: { required_status_checks: [{ context: 'CI Gate', integration_id: 15368 }] } }],
  ciWorkflow: { id: CI_WORKFLOW_ID, path: '.github/workflows/ci.yml', state: 'active' },
  releaseWorkflow: { id: RELEASE_WORKFLOW_ID, path: '.github/workflows/release.yml', state: 'active' },
  ancestry: Object.fromEntries([C, P].map(sha => [sha, { status: 'ahead', merge_base_commit: { sha } }])),
  files: Object.fromEntries(POLICY_FILES.map(path => [path, [hashes[path], hashes[path], hashes[path]]])),
}; }
const input = { tag: TAG, source: C, policySha: P };

test('only the exact tag-push release context qualifies and the qualifier has no OIDC', () => {
  assert.deepEqual(releaseEnvironment(env, 'qualify'), { tag: TAG, policySha: C });
  for (const patch of [{ GITHUB_REPOSITORY: 'fork/secrets' }, { GITHUB_EVENT_NAME: 'workflow_dispatch' },
    { GITHUB_REF: 'refs/heads/main' }, { GITHUB_WORKFLOW_REF: `${REPO}/.github/workflows/other.yml@refs/tags/${TAG}` },
    { GITHUB_SHA: 'not-sha' }, { RELEASE_TAG: 'v01.8.5' }, { ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'FAKE_UNUSABLE_TEST_VALUE' },
    { ACTIONS_ID_TOKEN_REQUEST_URL: 'https://invalid.example' }]) {
    assert.throws(() => releaseEnvironment({ ...env, ...patch }, 'qualify'));
  }
});
test('candidate package identities and strict tag versions bind data before dispatch', () => {
  const values = [{ name: 'phantom-secrets', version: '0.8.5' }, { name: 'phantom-secrets-mcp', version: '0.8.5' }];
  assert.doesNotThrow(() => validateVersions(TAG, values));
  for (const patch of [[values[1], values[0]], [values[0]], [...values, values[0]],
    [values[0], { ...values[1], version: '0.8.4' }], [values[0], { ...values[1], version: '0.8.5\n' }]]) {
    assert.throws(() => validateVersions(TAG, patch));
  }
});
test('every repository/workflow/manual tag/source/current-attempt binding is mandatory', () => {
  assert.doesNotThrow(() => validateRun(run(), C, TAG, RUN, ATTEMPT, true));
  for (const patch of [{ repository: { id: 1, full_name: REPO } }, { repository: { id: REPOSITORY_ID, full_name: 'fork/secrets' } },
    { head_repository: { id: 1, full_name: 'fork/secrets' } }, { workflow_id: 1 }, { path: 'ci.yml' },
    ...['push', 'schedule', 'pull_request', 'merge_group', 'workflow_run', 'workflow_call'].map(event => ({ event })),
    { head_branch: 'main' }, { head_branch: 'v0.8.4' }, { head_sha: P }, { id: RUN + 1 }, { run_attempt: ATTEMPT + 1 },
    { status: 'unknown' }, { status: 'in_progress' }, { conclusion: 'failure' }, { conclusion: 'cancelled' }, { conclusion: 'skipped' }]) {
    assert.throws(() => validateRun({ ...run(), ...patch }, C, TAG, RUN, ATTEMPT, true));
  }
});
test('all twenty exact roles are complete; only the known docs role may be skipped', () => {
  assert.equal(validateJobs(jobs(), RUN, ATTEMPT).length, 20);
  for (let index = 0; index < 20; index++) {
    for (const change of [doc => { doc.jobs.splice(index, 1); doc.total_count--; },
      doc => { doc.jobs[index].run_attempt++; }, doc => { doc.jobs[index].status = 'in_progress'; },
      doc => { doc.jobs[index].conclusion = 'cancelled'; }, doc => { doc.jobs[index].name = 'unknown role'; }]) {
      const doc = jobs(); change(doc); assert.throws(() => validateJobs(doc, RUN, ATTEMPT));
    }
  }
  for (const change of [doc => { doc.jobs.push(doc.jobs[0]); doc.total_count++; },
    doc => { doc.jobs[1].id = doc.jobs[0].id; }, doc => { doc.total_count++; },
    doc => { doc.jobs.find(job => job.name === 'Docs command check').conclusion = 'success'; }]) {
    const doc = jobs(); change(doc); assert.throws(() => validateJobs(doc, RUN, ATTEMPT));
  }
});
test('success cannot hide missing, skipped, duplicated or failed critical full steps', () => {
  for (const [jobName, names] of Object.entries(CRITICAL_STEPS)) for (const name of names) {
    for (const change of [job => { job.steps = job.steps.filter(step => step.name !== name); },
      job => { job.steps.find(step => step.name === name).conclusion = 'skipped'; },
      job => { job.steps.find(step => step.name === name).conclusion = 'failure'; },
      job => { job.steps.find(step => step.name === name).status = 'in_progress'; },
      job => { job.steps.push({ name, status: 'completed', conclusion: 'success' }); }]) {
      const doc = jobs(); change(doc.jobs.find(job => job.name === jobName));
      assert.throws(() => validateJobs(doc, RUN, ATTEMPT));
    }
  }
});
test('the actual failed 084 installer step is ineligible even behind a forged green job/run', () => {
  const doc = jobs(); const linux = doc.jobs.find(job => job.name === 'Test (ubuntu-latest)');
  linux.steps.find(step => step.name === 'Run direct installer offline tests').conclusion = 'failure';
  assert.throws(() => validateJobs(doc, RUN, ATTEMPT));
  for (const name of ['Run tests with coverage', 'Run ignored tests (real OS keychain)']) {
    const doc = jobs(); for (const job of doc.jobs) job.steps = job.steps.filter(step => step.name !== name);
    assert.throws(() => validateJobs(doc, RUN, ATTEMPT));
  }
});
test('protected benign main advances pass but revoked protection, ancestry or any policy member fails', () => {
  assert.doesNotThrow(() => validatePolicy(input, policyEvidence(), hashes));
  for (const change of [e => { e.repo.id++; }, e => { e.repo.default_branch = 'other'; },
    e => { e.branch.protected = false; }, e => { e.rules = []; },
    e => { e.rules[0].parameters.required_status_checks[0].integration_id = 1; },
    e => { e.ciWorkflow.state = 'disabled_manually'; }, e => { e.releaseWorkflow.path = '.github/workflows/other.yml'; },
    e => { e.ancestry[C].status = 'diverged'; }, e => { e.ancestry[P].merge_base_commit.sha = C; }]) {
    const e = policyEvidence(); change(e); assert.throws(() => validatePolicy(input, e, hashes));
  }
  for (const path of POLICY_FILES) for (const index of [0, 1, 2]) {
    const e = policyEvidence(); e.files[path][index] = 'f'.repeat(64);
    assert.throws(() => validatePolicy(input, e, hashes));
  }
  const e = policyEvidence(); delete e.files[POLICY_FILES[0]];
  assert.throws(() => validatePolicy(input, e, hashes));
});
test('only an exact annotated commit tag is accepted', async () => {
  for (const patch of [{ ref: 'refs/tags/v0.8.4' }, { object: { type: 'commit', sha: C } }, { object: { type: 'tag', sha: 'bad' } }]) {
    await assert.rejects(resolveAnnotatedTag(TAG, async () => ({ ref: `refs/tags/${TAG}`, object: { type: 'tag', sha: TAG_OBJECT }, ...patch })));
  }
  await assert.rejects(resolveAnnotatedTag(TAG, async path => path.startsWith('git/ref') ?
    { ref: `refs/tags/${TAG}`, object: { type: 'tag', sha: TAG_OBJECT } } : { tag: TAG, object: { type: 'tree', sha: C } }));
});

function harness(options = {}) {
  let time = 0, dispatched = 0, listed = 0, read = 0, branchReads = 0, visible = options.visible ?? true;
  const evidence = policyEvidence();
  const api = async (path, request) => {
    if (path === `git/ref/tags/${TAG}`) return { ref: `refs/tags/${TAG}`, object: { type: 'tag', sha: TAG_OBJECT } };
    if (path === `git/tags/${TAG_OBJECT}`) return { tag: TAG, object: { type: 'commit', sha: options.tagMoved && branchReads > 1 ? P : C } };
    if (path === '') return evidence.repo;
    if (path === 'branches/main') { branchReads++; return evidence.branch; }
    if (path === 'rules/branches/main') return evidence.rules;
    if (path === 'actions/workflows/ci.yml') return evidence.ciWorkflow;
    if (path === 'actions/workflows/release.yml') return evidence.releaseWorkflow;
    if (path.startsWith('compare/')) return evidence.ancestry[path.slice(8, 48)];
    if (path.startsWith('contents/')) {
      const name = path.slice(9).split('?')[0];
      const content = name === 'npm/package.json' ? JSON.stringify({ name: 'phantom-secrets', version: '0.8.5' }) :
        name === 'npm-mcp/package.json' ? JSON.stringify({ name: 'phantom-secrets-mcp', version: '0.8.5' }) :
        options.revoke && branchReads > 1 && name === POLICY_FILES[0] ? 'revoked policy' : bytes;
      return { type: 'file', path: name, encoding: 'base64', size: Buffer.byteLength(content), content: Buffer.from(content).toString('base64') };
    }
    if (path.startsWith(`actions/workflows/${CI_WORKFLOW_ID}/runs?`)) {
      listed++; const values = visible ? [run()] : [];
      if (options.newerFailed && visible) values.push({ ...run(), id: RUN + 1, conclusion: 'failure' });
      if (options.newerAfter && branchReads > 1) values.push({ ...run(), id: RUN + 1,
        status: options.newerAfter === 'pending' ? 'in_progress' : 'completed',
        conclusion: options.newerAfter === 'pending' ? null : options.newerAfter });
      if (options.duplicateRuns && visible) values.push(run());
      return { total_count: values.length + (options.incompleteList ? 1 : 0), workflow_runs: values };
    }
    if (path === `actions/workflows/${CI_WORKFLOW_ID}/dispatches`) {
      dispatched++; assert.deepEqual(request, { method: 'POST', body: { ref: TAG } });
      visible = !options.neverVisible;
      if (options.uncertain) throw new Error('synthetic lost response');
      return;
    }
    if (path.startsWith('actions/runs/') && !path.includes('/attempts/')) {
      read++; const value = run();
      if (options.newerFailed && path.endsWith(String(RUN + 1))) { value.id++; value.conclusion = 'failure'; }
      if (options.rerun && read > 1) value.run_attempt++;
      if (options.pending) { value.status = 'in_progress'; value.conclusion = null; }
      return value;
    }
    if (path === `actions/runs/${RUN}/attempts/${ATTEMPT}/jobs?per_page=100`) return jobs();
    throw new Error('unexpected synthetic API path');
  };
  return { deps: { api, hashes, now: () => time, sleep: async ms => { time += ms; } }, counts: () => ({ time, dispatched, listed, read }) };
}
test('existing exact full proof is reused and rechecked without duplicate dispatch', async () => {
  const h = harness(), result = await runGate('qualify', env, h.deps);
  assert.equal(result.runId, RUN); assert.equal(result.attempt, ATTEMPT); assert.equal(result.source, C);
  assert.equal(result.jobs.length, 20); assert.equal(h.counts().dispatched, 0);
});
test('one uncertain dispatch reconciles by bounded reads, never resends', async () => {
  const h = harness({ visible: false, uncertain: true });
  assert.equal((await runGate('qualify', env, h.deps)).runId, RUN); assert.equal(h.counts().dispatched, 1);
  const missing = harness({ visible: false, uncertain: true, neverVisible: true });
  await assert.rejects(runGate('qualify', env, missing.deps), /no-resend/); assert.equal(missing.counts().dispatched, 1);
});
test('a pending producer is reused until the finite deadline without redispatch', async () => {
  const h = harness({ pending: true }); await assert.rejects(runGate('qualify', env, h.deps), /deadline/);
  assert.equal(h.counts().dispatched, 0);
});
test('newer failed evidence cannot be hidden behind older green, and ambiguous inventory refuses', async () => {
  for (const options of [{ newerFailed: true }, { duplicateRuns: true }, { incompleteList: true }]) {
    const h = harness(options); await assert.rejects(runGate('qualify', env, h.deps)); assert.equal(h.counts().dispatched, 0);
  }
});
test('every fresh verification refuses attempt races, tag movement and policy revocation', async () => {
  for (const options of [{ rerun: true }, { tagMoved: true }, { revoke: true }]) {
    const h = harness(options); await assert.rejects(runGate('verify', env, h.deps)); assert.equal(h.counts().dispatched, 0);
  }
  assert.equal((await runGate('verify', env, harness().deps)).runId, RUN);
});
test('bounded GitHub reads refuse redirects and oversized bodies without exposing credentials', async () => {
  const savedFetch = globalThis.fetch, savedToken = process.env.GH_TOKEN;
  process.env.GH_TOKEN = 'FAKE_UNUSABLE_TEST_VALUE';
  try {
    const calls = [];
    globalThis.fetch = async (url, options) => { calls.push({ url, options }); return new Response(null, { status: 302, headers: { location: 'https://invalid.example' } }); };
    await assert.rejects(githubJson('branches/main'), /unavailable/); assert.equal(calls.length, 1);
    assert.equal(calls[0].options.redirect, 'error'); assert.equal(new URL(calls[0].url).hostname, 'api.github.com');
    globalThis.fetch = async () => new Response('x', { headers: { 'content-length': String(8 * 1024 * 1024 + 1) } });
    await assert.rejects(githubJson('branches/main'), /unavailable/);
  } finally { globalThis.fetch = savedFetch; if (savedToken === undefined) delete process.env.GH_TOKEN; else process.env.GH_TOKEN = savedToken; }
});


function jobBlock(text, name) {
  const found = text.indexOf(`\n  ${name}:\n`); assert.ok(found >= 0);
  const rest = text.slice(found + 1);
  // A job ends only at another two-space mapping key, not a deeper step.
  const boundary = /\n  [a-z][a-z-]+:\n/.exec(rest.slice(rest.indexOf('\n') + 1));
  return boundary ? rest.slice(0, rest.indexOf('\n') + 1 + boundary.index) : rest;
}
function runAfter(block, name) {
  const after = block.slice(block.indexOf(`      - name: ${name}\n`));
  assert.ok(after.startsWith(`      - name: ${name}\n`));
  const body = after.match(/        run: \|\n((?:          .*\n|\n)+)/);
  assert.ok(body); return body[1].split('\n').map(line => line.startsWith('          ') ? line.slice(10) : line).join('\n');
}
test('workflow wires the full guard before native producers, attestations and every public/npm write', () => {
  const text = readFileSync(new URL('../../.github/workflows/release.yml', import.meta.url), 'utf8');
  const qualify = jobBlock(text, 'qualify'), build = jobBlock(text, 'build-and-verify');
  assert.match(qualify, /permissions:\n      contents: read\n      actions: write/);
  assert.doesNotMatch(qualify, /id-token:|secrets\./);
  assert.match(qualify, /node scripts\/release\/qualify-full-ci\.mjs qualify/);
  assert.match(build, /needs: qualify/);
  const attest = jobBlock(text, 'attest');
  assert.match(attest, /needs: \[qualify, build-and-verify\]/);
  assert.equal((attest.match(/run: node scripts\/release\/qualify-full-ci\.mjs verify/g) ?? []).length, 7);
  const steps = attest.split(/(?=      - (?:name|uses):)/).filter(step => step.startsWith('      -'));
  for (let i = 0; i < steps.length; i++) if (/uses: actions\/attest@/.test(steps[i])) {
    assert.match(steps[i - 1], /run: node scripts\/release\/qualify-full-ci\.mjs verify/);
  }
  for (const name of ['attest', 'release', 'npm-publish']) {
    const block = jobBlock(text, name);
    assert.match(block, /actions: read/);
    for (const field of ['FULL_CI_RUN_ID', 'FULL_CI_ATTEMPT', 'FULL_CI_SOURCE']) assert.ok(block.includes(field));
  }
  const release = jobBlock(text, 'release');
  const beforeDraft = release.slice(0, release.indexOf('      - name: Create release\n'));
  assert.match(beforeDraft.trimEnd(), /node scripts\/release\/qualify-full-ci\.mjs verify$/);
  assert.match(runAfter(release, 'Publish the organization-enforced immutable release'), /node scripts\/release\/qualify-full-ci\.mjs verify\n[ \t]*gh release edit/);
  assert.match(runAfter(jobBlock(text, 'npm-publish'), 'Publish with provenance'), /node \.\.\/scripts\/release\/qualify-full-ci\.mjs verify\n[ \t]*npm publish/);
  for (const action of text.matchAll(/uses: ([^\n]+)/g)) assert.match(action[1].split(' #')[0], /^(?:\.\/|[^ ]+@[a-f0-9]{40}$)/);
});
test('an actual failed guard prevents the shell from reaching public and npm mutators', () => {
  const text = readFileSync(new URL('../../.github/workflows/release.yml', import.meta.url), 'utf8');
  const home = mkdtempSync(join(tmpdir(), 'secrets-write-boundary-'));
  try {
    const bin = join(home, 'bin'), marker = join(home, 'wrote'); mkdirSync(bin);
    writeFileSync(join(bin, 'node'), '#!/bin/sh\nif [ "$1" = "-p" ]; then printf 0.8.5; exit 0; fi\nexit "$VERIFY_EXIT"\n');
    writeFileSync(join(bin, 'gh'), '#!/bin/sh\nprintf public > "$WRITE_MARKER"\n');
    writeFileSync(join(bin, 'npm'), '#!/bin/sh\nif [ "$1" = "view" ]; then exit 1; fi\nprintf npm > "$WRITE_MARKER"\n');
    for (const name of ['node', 'gh', 'npm']) chmodSync(join(bin, name), 0o700);
    const scripts = [runAfter(jobBlock(text, 'release'), 'Publish the organization-enforced immutable release'),
      runAfter(jobBlock(text, 'npm-publish'), 'Publish with provenance')];
    for (const script of scripts) for (const status of ['19', '0']) {
      rmSync(marker, { force: true });
      const child = spawnSync('/bin/bash', ['-c', script], { env: { HOME: home, PATH: bin + ':/usr/bin:/bin',
        VERIFY_EXIT: status, WRITE_MARKER: marker, GITHUB_REF_NAME: TAG, PKG_NAME: 'phantom-secrets' }, encoding: 'utf8', timeout: 5000 });
      assert.equal(child.status, Number(status), child.stderr);
      assert.equal(existsSync(marker), status === '0');
    }
  } finally { rmSync(home, { recursive: true, force: true }); }
});


test('a retried release reuses visible proof but never replays an unresolved dispatch', async () => {
  const retry = { ...env, GITHUB_RUN_ATTEMPT: '2' };
  assert.equal((await runGate('qualify', retry, harness().deps)).runId, RUN);
  const missing = harness({ visible: false });
  await assert.rejects(runGate('qualify', retry, missing.deps), /no-resend/);
  assert.equal(missing.counts().dispatched, 0);
});

test('critical evidence steps are bound to the actual owning CI jobs and manual-full selection', () => {
  const ci = readFileSync(new URL('../../.github/workflows/ci.yml', import.meta.url), 'utf8');
  const owners = {
    'Test (macos-latest)': 'test', 'Test (ubuntu-latest)': 'test', 'Test (windows-latest)': 'test',
    'Ignored Tests (macos-latest)': 'test-ignored', 'Ignored Tests (ubuntu-latest)': 'test-ignored', 'Ignored Tests (windows-latest)': 'test-ignored',
    'Lint': 'lint', 'Rust dependency policy': 'dependency-policy', 'Windows ARM64 source check': 'windows-arm-source-check',
    'npm wrapper tests and package inspection': 'npm-wrappers', 'Web security, tests, and build': 'web',
    'Source secret scan': 'secret-scan', 'Secret-shape scan': 'secret-shape', 'Crate publication contract': 'crate-publication-contract',
    'Temporal codec example tests': 'temporal-codec-example', 'CI Gate': 'gate', 'Upload coverage': 'coverage', 'Daily fixup queue': 'fixup-queue',
  };
  for (const [name, steps] of Object.entries(CRITICAL_STEPS)) {
    const block = jobBlock(ci, owners[name]);
    for (const step of steps) {
      const escaped = step.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      assert.equal([...block.matchAll(new RegExp(`^ {6}(?:- name: |  name: )${escaped}$`, 'gm'))].length, 1, `${name}: ${step} must exist once in its actual producer`);
    }
  }
  assert.match(jobBlock(ci, 'test-ignored'), /if: github\.event_name == 'workflow_dispatch'/);
  assert.match(jobBlock(ci, 'test'), /cargo nextest run --workspace --all-targets --locked --no-fail-fast/);
  assert.match(jobBlock(ci, 'test'), /node --test\n\s+scripts\/installer-copy-byte-consistency\.test\.mjs/);
  assert.match(jobBlock(ci, 'coverage'), /github\.event_name == 'workflow_dispatch'/);
});


test('a fresh later exact producer revokes the frozen tuple without switching or dispatching', async () => {
  for (const mode of ['qualify', 'verify']) for (const newerAfter of ['failure', 'pending', 'success']) {
    const h = harness({ newerAfter });
    await assert.rejects(runGate(mode, env, h.deps), /latest-exact-producer-changed/);
    assert.equal(h.counts().dispatched, 0);
  }
});
