import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

const guide = readFileSync(new URL('../docs/agents.md', import.meta.url), 'utf8');
const checks = [...guide.matchAll(/phantom exec -- sh -c '\n([\s\S]*?)\n'/g)]
  .map(match => match[1]);

function checkFor(needle) {
  const matches = checks.filter(check => check.includes(needle));
  assert.equal(matches.length, 1, 'expected exactly one documented environment check');
  return matches[0];
}

function runCheck(script, variables, expectedStatus, expectedOutput = '') {
  const home = mkdtempSync(join(tmpdir(), 'phantom-doc-shell-'));
  try {
    const result = spawnSync('sh', ['-c', script], {
      env: { PATH: process.env.PATH ?? '', HOME: home, ...variables },
      encoding: 'utf8',
      timeout: 5000,
    });
    // Never attach child output to an assertion: a regression could print a value.
    assert.ok(!result.error, 'documented check could not execute');
    assert.equal(result.status, expectedStatus, 'unexpected check exit status');
    assert.ok(result.stdout === expectedOutput, 'check printed unexpected output');
    assert.ok(result.stderr === '', 'check printed unexpected diagnostics');
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}

const placeholder = checkFor('token=${OPENAI_API_KEY#phm_}');
const route = checkFor('port=${route%%/*}');
const passphrase = checkFor('${PHANTOM_VAULT_PASSPHRASE+x}');
const bearer = 'a'.repeat(64);
const routeUrl = (port = '12345') => `http://127.0.0.1:${port}/openai/_phantom/${bearer}/`;

test('placeholder check accepts the full shape and prints a fixed confirmation', () => {
  runCheck(placeholder, { OPENAI_API_KEY: `phm_${'b'.repeat(64)}` }, 0,
    'OPENAI_API_KEY: session placeholder present\n');
});

for (const [name, variables] of [
  ['missing variable', {}],
  ['empty variable', { OPENAI_API_KEY: '' }],
  ['wrong prefix', { OPENAI_API_KEY: `raw_${'b'.repeat(64)}` }],
  ['short placeholder', { OPENAI_API_KEY: `phm_${'b'.repeat(63)}` }],
  ['long placeholder', { OPENAI_API_KEY: `phm_${'b'.repeat(65)}` }],
  ['nonhex placeholder', { OPENAI_API_KEY: `phm_${'g'.repeat(64)}` }],
]) {
  test(`placeholder check silently rejects ${name}`, () => {
    runCheck(placeholder, variables, 1);
  });
}

for (const port of ['1', '12345', '65535']) {
  test(`route check accepts valid port ${port} and prints a fixed confirmation`, () => {
    runCheck(route, { PHANTOM_PROXY_TOKEN: bearer, OPENAI_BASE_URL: routeUrl(port) }, 0,
      'OPENAI_BASE_URL: authenticated loopback route present\n');
  });
}

for (const [name, url] of [
  ['remote userinfo authority', routeUrl('12345@remote.example')],
  ['nonnumeric port', routeUrl('invalid')],
  ['empty port', routeUrl('')],
  ['zero port', routeUrl('0')],
  ['out-of-range port', routeUrl('65536')],
  ['oversized port', routeUrl('9'.repeat(40))],
  ['remote host', routeUrl().replace('127.0.0.1', 'remote.example')],
  ['wrong bearer', routeUrl().replace(bearer, 'c'.repeat(64))],
  ['extra path', `${routeUrl()}extra`],
  ['query suffix', `${routeUrl()}?extra=1`],
  ['missing URL', ''],
]) {
  test(`route check silently rejects ${name}`, () => {
    runCheck(route, { PHANTOM_PROXY_TOKEN: bearer, OPENAI_BASE_URL: url }, 1);
  });
}

test('route check silently rejects a missing bearer', () => {
  runCheck(route, { OPENAI_BASE_URL: routeUrl() }, 1);
});

test('passphrase absence check prints only a fixed confirmation', () => {
  runCheck(passphrase, {}, 0, 'PHANTOM_VAULT_PASSPHRASE: absent\n');
});

for (const [name, value] of [['empty', ''], ['nonempty', 'doc-test-only']]) {
  test(`passphrase absence check silently rejects a ${name} inherited variable`, () => {
    runCheck(passphrase, { PHANTOM_VAULT_PASSPHRASE: value }, 1);
  });
}

const harness = readFileSync(new URL('./test-docs-agents.sh', import.meta.url), 'utf8');
const scanBlocks = [...harness.matchAll(/^project_id=\$\(sed[\s\S]*?^assert_count=\$\(\(assert_count \+ 1\)\)$/gm)];
assert.equal(scanBlocks.length, 1, 'expected exactly one walkthrough transcript scan');
const transcriptScan = scanBlocks[0][0];
const projectId = 'd'.repeat(64);

for (const [name, log, expectedStatus] of [
  ['allows the exact public project ID status line', `  Project ID:  ${projectId}\n`, 0],
  ['rejects the same digest without its public field label', `${projectId}\n`, 1],
  ['rejects the same digest in a placeholder', `phm_${projectId}\n`, 1],
  ['rejects the same digest in a bearer URL', `http://127.0.0.1:12345/openai/_phantom/${projectId}/\n`, 1],
  ['rejects extra content after the public status line', `  Project ID:  ${projectId} extra\n`, 1],
]) {
  test(`walkthrough transcript scan ${name}`, () => {
    const home = mkdtempSync(join(tmpdir(), 'phantom-doc-transcript-'));
    try {
      const work = join(home, 'project');
      const logs = join(home, 'logs');
      mkdirSync(work);
      mkdirSync(logs);
      writeFileSync(join(work, '.phantom.toml'), `[phantom]\nproject_id = "${projectId}"\n`);
      writeFileSync(join(logs, 'block-01.log'), log);
      const script = [
        'set -euo pipefail',
        'say() { printf "%s\\n" "$*"; }',
        'fail() { say "FAIL: $*" >&2; exit 1; }',
        'ASSERT_FAILS=0',
        'assert_count=0',
        transcriptScan,
        '(( ASSERT_FAILS == 0 ))',
      ].join('\n');
      const result = spawnSync('bash', ['-c', script], {
        env: { PATH: process.env.PATH ?? '', HOME: home, SANDBOX: home, WORK: work, LOGS: logs },
        encoding: 'utf8',
        timeout: 5000,
      });
      assert.ok(!result.error, 'walkthrough scan could not execute');
      assert.equal(result.status, expectedStatus, 'unexpected transcript scan exit status');
      assert.ok(result.stdout === '', 'transcript scan exposed unexpected output');
      const diagnostic = expectedStatus === 0 ? ''
        : 'FAIL assert: mapping, session placeholder, or proxy bearer printed\n';
      assert.ok(result.stderr === diagnostic, 'transcript scan exposed unexpected diagnostics');
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });
}
