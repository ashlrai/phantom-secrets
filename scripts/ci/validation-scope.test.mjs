import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { DIAGNOSTIC_SCOPE, selectValidationScope, validationScope } from './validation-scope.mjs';
import { REPO, REPOSITORY_ID } from '../release/qualify-full-ci.mjs';

const env = { VALIDATION_SCOPE: DIAGNOSTIC_SCOPE, GITHUB_EVENT_NAME: 'workflow_dispatch',
  GITHUB_REPOSITORY: REPO, GITHUB_REPOSITORY_ID: String(REPOSITORY_ID), GITHUB_REF: 'refs/heads/main',
  GITHUB_WORKFLOW_REF: `${REPO}/.github/workflows/ci.yml@refs/heads/main`, GITHUB_SHA: 'a'.repeat(40) };
const repository = { id: REPOSITORY_ID, full_name: REPO, default_branch: 'main' };
const branch = { name: 'main', protected: true, commit: { sha: 'b'.repeat(40) } };

test('full remains the default for manual, scheduled, PR and reusable-workflow events without API calls', async () => {
  for (const event of ['workflow_dispatch', 'schedule', 'pull_request', 'merge_group', 'workflow_call']) {
    for (const scope of [undefined, '', 'full']) assert.equal(await selectValidationScope({
      GITHUB_EVENT_NAME: event, VALIDATION_SCOPE: scope,
    }, () => { throw new Error('full must not need a new API dependency'); }), 'full');
  }
  for (const value of ['windows', 'diagnostics', 'FULL', ' full', 'full\n', '__proto__']) {
    assert.throws(() => validationScope({ ...env, VALIDATION_SCOPE: value }), /unknown/);
  }
});
test('diagnostics require the canonical protected default branch and exact manual workflow context', async () => {
  const calls = [];
  assert.equal(await selectValidationScope(env, async path => { calls.push(path); return path ? branch : repository; }), DIAGNOSTIC_SCOPE);
  assert.deepEqual(calls, ['', 'branches/main']);
  for (const patch of [{ GITHUB_EVENT_NAME: 'schedule' }, { GITHUB_EVENT_NAME: 'workflow_call' },
    { GITHUB_REPOSITORY: 'fork/secrets' }, { GITHUB_REPOSITORY_ID: '1' }, { GITHUB_REF: 'refs/tags/v0.8.5' },
    { GITHUB_REF: 'refs/heads/other' }, { GITHUB_SHA: 'bad' },
    { GITHUB_WORKFLOW_REF: `${REPO}/.github/workflows/other.yml@refs/heads/main` }]) {
    await assert.rejects(selectValidationScope({ ...env, ...patch }, () => { throw new Error('must refuse before reads'); }), /untrusted/);
  }
  for (const repo of [{ ...repository, id: 1 }, { ...repository, full_name: 'fork/secrets' }, { ...repository, default_branch: 'other' }]) {
    await assert.rejects(selectValidationScope(env, async path => path ? branch : repo), /not-protected/);
  }
  for (const value of [{ ...branch, protected: false }, { ...branch, name: 'other' }, { ...branch, commit: { sha: 'bad' } }]) {
    await assert.rejects(selectValidationScope(env, async path => path ? value : repository), /not-protected/);
  }
  await assert.rejects(selectValidationScope(env, async () => { throw new Error('unavailable'); }), /unavailable/);
});

function jobBlock(text, name) {
  const rest = text.slice(text.indexOf(`\n  ${name}:\n`) + 1);
  return rest.split(/\n(?=  [a-z][a-z-]*:\n)/)[0];
}
function workflow() { return readFileSync(new URL('../../.github/workflows/ci.yml', import.meta.url), 'utf8'); }
function runGate(needs, event = 'workflow_dispatch') {
  const block = jobBlock(workflow(), 'gate');
  const script = block.match(/          node <<'NODE'\n([\s\S]*?)          NODE/)?.[1];
  assert.ok(script);
  return spawnSync(process.execPath, ['-e', script], { encoding: 'utf8', env: { NEEDS: JSON.stringify(needs), EVENT: event }, timeout: 5000 });
}
function diagnosticNeeds() {
  const skipped = ['test-ignored', 'lint', 'dependency-policy', 'windows-arm-source-check', 'npm-wrappers', 'web',
    'secret-scan', 'secret-shape', 'crate-publication-contract', 'temporal-codec-example', 'docs-commands'];
  return { changes: { result: 'success', outputs: { scope: DIAGNOSTIC_SCOPE } }, test: { result: 'success' },
    ...Object.fromEntries(skipped.map(name => [name, { result: 'skipped' }])) };
}
test('the actual diagnostic gate requires its selected Windows job and refuses omitted or unexpected roles', () => {
  assert.equal(runGate(diagnosticNeeds()).status, 0);
  for (const status of ['failure', 'cancelled', 'skipped', 'pending']) {
    const needs = diagnosticNeeds(); needs.test.result = status; assert.notEqual(runGate(needs).status, 0);
  }
  for (const change of [n => { delete n.web; }, n => { n.extra = { result: 'skipped' }; },
    n => { n.web.result = 'success'; }, n => { n.changes.outputs.scope = 'unknown'; }, n => { n.changes.result = 'failure'; }]) {
    const needs = diagnosticNeeds(); change(needs); assert.notEqual(runGate(needs).status, 0);
  }
  assert.notEqual(runGate(diagnosticNeeds(), 'schedule').status, 0);
});
test('the actual unchanged full gate still requires every full role and rejects diagnostic omissions', () => {
  const needs = diagnosticNeeds();
  needs.changes.outputs = { scope: 'full', rust: 'true', web: 'true', temporal_example: 'true', docs_commands: 'false', platform: 'true' };
  for (const [name, value] of Object.entries(needs)) if (name !== 'changes' && name !== 'docs-commands') value.result = 'success';
  assert.equal(runGate(needs).status, 0);
  for (const name of Object.keys(needs).filter(name => !['changes', 'docs-commands'].includes(name))) {
    const changed = structuredClone(needs); changed[name].result = 'skipped'; assert.notEqual(runGate(changed).status, 0);
  }
});
test('workflow omits all unrelated diagnostics jobs, OIDC coverage and fixup without changing the Windows test body', () => {
  const ci = workflow();
  assert.match(ci, /validation_scope:\n\s+description:.*\n\s+type: choice\n\s+default: full\n\s+options: \[full, windows-native-diagnostics\]/);
  assert.match(jobBlock(ci, 'test'), /needs\.changes\.outputs\.scope == 'windows-native-diagnostics' && '\["windows-latest"\]'/);
  assert.match(jobBlock(ci, 'test'), /timeout-minutes: 20/);
  for (const name of ['coverage', 'test-ignored', 'lint', 'dependency-policy', 'windows-arm-source-check', 'npm-wrappers', 'web',
    'secret-scan', 'secret-shape', 'crate-publication-contract', 'temporal-codec-example', 'docs-commands', 'fixup-queue']) {
    assert.match(jobBlock(ci, name).match(/^    if: (.*)$/m)?.[1] ?? '', /inputs\.validation_scope != 'windows-native-diagnostics'/, name);
  }
  assert.match(jobBlock(ci, 'changes'), /- name: Validate full scope\n\s+if: steps\.scope\.outputs\.scope == 'full'/);
  assert.doesNotMatch(jobBlock(ci, 'changes'), /id-token:|actions: write|secrets\.(?!GITHUB_TOKEN)/);
});


test('actual PR and merge-queue gate selections retain the fast roles and reject daily-only execution', () => {
  for (const event of ['pull_request', 'merge_group']) {
    const needs = diagnosticNeeds();
    needs.changes.outputs = { scope: 'full', rust: 'true', web: 'true', temporal_example: 'true', docs_commands: 'true', platform: 'true' };
    for (const name of ['lint', 'npm-wrappers', 'dependency-policy', 'secret-scan', 'secret-shape']) needs[name].result = 'success';
    needs.test.result = 'skipped';
    assert.equal(runGate(needs, event).status, 0);
    needs.test.result = 'success'; assert.notEqual(runGate(needs, event).status, 0);
  }
});
