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
const installers = [
  ['repository', join(repo, 'scripts', 'install.sh')],
  ['public', join(repo, 'apps', 'web', 'public', 'install.sh')],
];

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Point-failure shims for every staging-creation step. PHANTOM_TEST_FAIL_SEAM
// names the one step that fails; every shim delegates all other calls to the
// real tool, so the installer reaches the named step and must then stop
// before any download or promotion. mktemp always records its invocations,
// which lets the later seams prove the stage itself was created before they
// fired. The mkdir shim reproduces mkdir's left-to-right behavior: it creates
// `download` and then fails on `candidate`, leaving a partially created stage
// tree that the cleanup trap must still remove.
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
      if [ "$PHANTOM_TEST_FAIL_SEAM" = mktemp ]; then
        printf 'mktemp: injected staging-directory failure\\n' >&2
        exit 1
      fi
      # mktemp "succeeds" but names a directory that does not exist.
      if [ "$PHANTOM_TEST_FAIL_SEAM" = missing ]; then
        printf '%s\\n' "\${arg%.install.XXXXXX}.install.missing-stage"
        exit 0
      fi
      ;;
  esac
done
exec /usr/bin/mktemp "$@"
`);
  writeFileSync(join(shims, 'chmod'), `#!/bin/sh
if [ "$PHANTOM_TEST_FAIL_SEAM" = chmod ] && [ "$1" = '700' ]; then
  case "$2" in
    *.install.*)
      printf 'chmod: injected staging-directory failure\\n' >&2
      exit 1
      ;;
  esac
fi
exec /bin/chmod "$@"
`);
  writeFileSync(join(shims, 'mkdir'), `#!/bin/sh
if [ "$PHANTOM_TEST_FAIL_SEAM" = mkdir ]; then
  staging=0
  for arg do
    case "$arg" in */download|*/candidate) staging=1 ;; esac
  done
  if [ "$staging" -eq 1 ]; then
    for arg do
      case "$arg" in
        */download) /bin/mkdir -m 700 "$arg" || exit 1 ;;
        */candidate)
          printf 'mkdir: injected staging-directory failure\\n' >&2
          exit 1
          ;;
      esac
    done
  fi
fi
exec /bin/mkdir "$@"
`);
  writeFileSync(join(shims, 'curl'), `#!/bin/sh
printf '%s\\n' "$*" >> "$PHANTOM_TEST_CURL_LOG"
exit 22
`);
  for (const name of ['mktemp', 'chmod', 'mkdir', 'curl']) {
    chmodSync(join(shims, name), 0o755);
  }
  return shims;
}

function runInstaller({ installer, root, seam }) {
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
      PHANTOM_TEST_FAIL_SEAM: seam,
    },
  });
  const calls = existsSync(mktempCalls)
    ? readFileSync(mktempCalls, 'utf8').split('--call--\n').slice(1)
      .map((entry) => entry.split('\n').filter(Boolean))
    : [];
  return { result, install, home, calls, curlLog };
}

// Every staging-creation failure shares the contract: exit 1 with the failed
// step named on stderr, no download attempted, the existing install
// byte-identical, and no stage, lock, or HOME leftovers.
function assertFailedStaging({ result, install, home, calls, curlLog, diagnostic, marker }) {
  const parent = dirname(install);
  assert.ifError(result.error);
  assert.equal(result.status, 1, result.stderr);
  // Both copies carry die() guards on top of errexit, so stderr names the
  // failed step, and the shim marker proves the injected failure is what fired.
  assert.match(result.stderr, diagnostic);
  assert.match(result.stderr, marker);
  assert.match(result.stdout, /target: /, 'the real installer ran up to the staging step');
  assert.doesNotMatch(result.stdout, /downloading|checksum/);
  assert.deepEqual(
    calls,
    [['-d', join(parent, '.bin.install.XXXXXX')]],
    'the only mktemp call must be the install-parent staging template',
  );
  assert.equal(existsSync(curlLog), false, 'staging failure must precede any download');
  assert.deepEqual(readdirSync(install), ['old-install']);
  assert.equal(readFileSync(join(install, 'old-install'), 'utf8'), 'preserve-me');
  assert.deepEqual(
    readdirSync(parent),
    ['bin'],
    'the lock and any staging leftovers must be cleaned up',
  );
  assert.deepEqual(readdirSync(home), [], 'HOME must contain no leftover files');
}

for (const [label, installer] of installers) {
  test(`${label} installer exits nonzero before download when mktemp cannot create the staging directory`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), `phantom-staging-failure-${label}-`)));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const { result, install, home, calls, curlLog } = runInstaller({
      installer, root, seam: 'mktemp',
    });

    assertFailedStaging({
      result,
      install,
      home,
      calls,
      curlLog,
      // The failed step also names the parent it could not stage in.
      diagnostic: new RegExp(
        `could not create a private staging directory in ${escapeRegExp(dirname(install))}`,
      ),
      marker: /mktemp: injected staging-directory failure/,
    });
  });

  test(`${label} installer exits nonzero before download when chmod cannot secure the staging directory`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), `phantom-staging-failure-${label}-`)));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const { result, install, home, calls, curlLog } = runInstaller({ installer, root, seam: 'chmod' });

    // The recorded mktemp call proves the stage existed; cleanup must remove
    // the empty stage root along with the lock.
    assertFailedStaging({
      result,
      install,
      home,
      calls,
      curlLog,
      diagnostic: /could not secure the staging directory/,
      marker: /chmod: injected staging-directory failure/,
    });
  });

  test(`${label} installer exits nonzero before download when mkdir cannot create the staging subdirectories`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), `phantom-staging-failure-${label}-`)));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const { result, install, home, calls, curlLog } = runInstaller({ installer, root, seam: 'mkdir' });

    // The shim created `download` before failing on `candidate`, so the
    // readdirSync(parent) check proves a partially created stage tree is
    // removed, not just an empty one.
    assertFailedStaging({
      result,
      install,
      home,
      calls,
      curlLog,
      diagnostic: /could not create staging directories/,
      marker: /mkdir: injected staging-directory failure/,
    });
  });

  test(`${label} installer exits nonzero before download when the staging directory is missing after mktemp`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), `phantom-staging-failure-${label}-`)));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const { result, install, home, calls, curlLog } = runInstaller({ installer, root, seam: 'missing' });

    // The installer must stop at the first use of the absent stage (chmod)
    // instead of downloading into, or promoting from, a path that is not there.
    assertFailedStaging({
      result,
      install,
      home,
      calls,
      curlLog,
      diagnostic: /could not secure the staging directory/,
      marker: /\.bin\.install\.missing-stage/,
    });
  });
}
