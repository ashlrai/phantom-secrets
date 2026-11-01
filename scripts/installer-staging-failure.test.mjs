import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync,
  realpathSync, rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';

const repo = resolve(import.meta.dirname, '..');
const repositoryInstaller = join(repo, 'scripts', 'install.sh');
const publicInstaller = join(repo, 'apps', 'web', 'public', 'install.sh');

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// A point-failure shim for the private stage's mktemp call. It records every
// invocation, fails only the `.<name>.install.XXXXXX` template, and delegates
// everything else to the real tool, so the installer reaches its staging step
// and must then stop before any download or promotion.
function makeShims(root) {
  const shims = join(root, 'shims');
  mkdirSync(shims);
  writeFileSync(join(shims, 'mktemp'), `#!/bin/sh
{
  printf -- '--call--\\n'
  printf '%s\\n' "$@"
} >> "$PHANTOM_TEST_MKTEMP_CALLS"
for arg do
  case "$arg" in
    *.install.XXXXXX)
      printf 'mktemp: injected staging-directory failure\\n' >&2
      exit 1
      ;;
  esac
done
exec /usr/bin/mktemp "$@"
`);
  writeFileSync(join(shims, 'curl'), `#!/bin/sh
printf '%s\\n' "$*" >> "$PHANTOM_TEST_CURL_LOG"
exit 22
`);
  for (const name of ['mktemp', 'curl']) chmodSync(join(shims, name), 0o755);
  return shims;
}

function runInstaller({ installer, root }) {
  const shims = makeShims(root);
  const home = join(root, 'home');
  const install = join(root, 'live', 'bin');
  const mktempCalls = join(root, 'mktemp-calls');
  const curlLog = join(root, 'curl.log');
  mkdirSync(home);
  mkdirSync(install, { recursive: true });
  writeFileSync(join(install, 'old-install'), 'preserve-me');
  const env = { ...process.env };
  for (const name of [
    'PHANTOM_REPO', 'PHANTOM_TAG', 'PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES',
    'PHANTOM_TEST_LOCAL_RELEASE_DIR', 'PHANTOM_TEST_FAIL_AFTER_PROMOTION',
    'PHANTOM_INSTALL_LOCK_WAIT_SECONDS', 'PHANTOM_INSTALL_LOCK_STALE_SECONDS',
    'PHANTOM_INSTALL_LOCK_HEARTBEAT_SECONDS',
  ]) delete env[name];
  const result = spawnSync('/bin/bash', [installer], {
    encoding: 'utf8',
    timeout: 30000,
    env: {
      ...env,
      HOME: home,
      SHELL: '/bin/bash',
      PATH: `${shims}:${process.env.PATH}`,
      PHANTOM_INSTALL_DIR: install,
      PHANTOM_TEST_MKTEMP_CALLS: mktempCalls,
      PHANTOM_TEST_CURL_LOG: curlLog,
    },
  });
  const calls = existsSync(mktempCalls)
    ? readFileSync(mktempCalls, 'utf8').split('--call--\n').slice(1)
      .map((entry) => entry.split('\n').filter(Boolean))
    : [];
  return { result, install, home, calls, curlLog };
}

test('repository installer exits nonzero before proceeding when mktemp cannot create the staging directory', (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-staging-failure-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const { result, install, calls, curlLog } = runInstaller({ installer: repositoryInstaller, root });
  const parent = dirname(install);

  assert.ifError(result.error);
  assert.equal(result.status, 1, result.stderr);
  assert.match(result.stderr, /could not create a private staging directory in /);
  assert.match(result.stderr, new RegExp(escapeRegExp(parent)));
  assert.match(result.stdout, /target: /, 'the real installer ran up to the staging step');
  assert.doesNotMatch(result.stdout, /downloading|checksum/);
  assert.deepEqual(
    calls,
    [['-d', join(parent, '.bin.install.XXXXXX')]],
    'the only mktemp call must be the install-parent staging template',
  );
  assert.equal(existsSync(curlLog), false, 'staging failure must precede any download');
  assert.equal(readFileSync(join(install, 'old-install'), 'utf8'), 'preserve-me');
  assert.deepEqual(
    readdirSync(parent),
    ['bin'],
    'the lock and any staging leftovers must be cleaned up',
  );
});

test('public installer copy also fails closed on staging-directory creation failure', (t) => {
  // The web copy drops the die() guards as a reviewed difference; `set -e`
  // must still stop it before downloads with an equally clean aftermath.
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-staging-failure-web-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const { result, install, calls, curlLog } = runInstaller({ installer: publicInstaller, root });
  const parent = dirname(install);

  assert.ifError(result.error);
  assert.equal(result.status, 1, result.stderr);
  assert.match(result.stderr, /mktemp: injected staging-directory failure/);
  assert.doesNotMatch(result.stdout, /downloading|checksum/);
  assert.deepEqual(calls, [['-d', join(parent, '.bin.install.XXXXXX')]]);
  assert.equal(existsSync(curlLog), false, 'staging failure must precede any download');
  assert.equal(readFileSync(join(install, 'old-install'), 'utf8'), 'preserve-me');
  assert.deepEqual(readdirSync(parent), ['bin']);
});
