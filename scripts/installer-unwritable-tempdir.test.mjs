import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync,
  realpathSync, rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const repo = resolve(import.meta.dirname, '..');
const installers = [
  ['repository', join(repo, 'scripts', 'install.sh')],
  ['public', join(repo, 'apps', 'web', 'public', 'install.sh')],
];
const isRoot = process.getuid?.() === 0;

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function permissionDiagnostic(stderr, paths) {
  const names = paths.map(escapeRegExp).join('|');
  return new RegExp(
    `^mkdir: (?:(?:cannot create directory [‘'](?:${names})[’'])|(?:${names})): Permission denied$`,
    'm',
  ).test(stderr);
}

test('permission diagnostics bind the denied operation to the exact parent or ancestor', () => {
  const sealed = '/fixture/Sealed', parent = sealed + '/install';
  for (const name of [sealed, parent]) for (const report of [
    `mkdir: ${name}: Permission denied`,
    `mkdir: cannot create directory ‘${name}’: Permission denied`,
    `mkdir: cannot create directory '${name}': Permission denied`,
  ]) assert.equal(permissionDiagnostic(report, [sealed, parent]), true);
  for (const report of [
    'mkdir: /fixture/sealed: Permission denied', 'mkdir: /other: Permission denied',
    `mkdir: ${parent}: File exists`, `mkdir: ${parent}: Permission denied extra`,
    `mkdir: /other: Permission denied\n${parent}`,
  ]) assert.equal(permissionDiagnostic(report, [sealed, parent]), false);
});

// Shared contract for every unwritable-temporary-directory failure: the run is
// stubbed (a curl shim records any download attempt), the destination keeps its
// prior contents byte-for-byte, and no stage, lock, or backup sibling survives.
function assertDestinationUnchanged(install, parent) {
  assert.deepEqual(readdirSync(install), ['old-install']);
  assert.equal(readFileSync(join(install, 'old-install'), 'utf8'), 'preserve-me');
  assert.deepEqual(
    readdirSync(parent),
    ['bin'],
    'no stage, lock, or backup sibling may remain beside the destination',
  );
}

function curlShim(shims) {
  writeFileSync(join(shims, 'curl'), `#!/bin/sh
printf '%s\\n' "$*" >> "$PHANTOM_TEST_CURL_LOG"
exit 22
`);
  chmodSync(join(shims, 'curl'), 0o755);
}

for (const [label, installer] of installers) {
  test(`${label} installer exits nonzero and preserves the destination when the staging parent is unwritable`, {
    skip: isRoot && 'root ignores directory permissions',
  }, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), `phantom-unwritable-tempdir-${label}-`)));
    const home = join(root, 'home');
    const shims = join(root, 'shims');
    const parent = join(root, 'live');
    const install = join(parent, 'bin');
    const curlLog = join(root, 'curl.log');
    mkdirSync(home);
    mkdirSync(shims);
    mkdirSync(install, { recursive: true });
    writeFileSync(join(install, 'old-install'), 'preserve-me');
    curlShim(shims);
    // The installer stages, locks, and backs up beside the destination, so a
    // read-only parent is its unwritable temporary directory. The lock cannot
    // be created there either, so the bounded lock wait reports the failure.
    chmodSync(parent, 0o555);
    t.after(() => {
      chmodSync(parent, 0o755);
      rmSync(root, { recursive: true, force: true });
    });

    const started = Date.now();
    const result = spawnSync('/bin/bash', [installer], {
      encoding: 'utf8',
      timeout: 30000,
      env: {
        PATH: `${shims}:${process.env.PATH}`,
        HOME: home,
        SHELL: '/bin/bash',
        PHANTOM_INSTALL_DIR: install,
        PHANTOM_TEST_CURL_LOG: curlLog,
        // Keep the bounded wait short; an unwritable parent can never take the lock.
        PHANTOM_INSTALL_LOCK_WAIT_SECONDS: '2',
      },
    });

    assert.ifError(result.error);
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stdout, /target: /, 'the real installer reached platform detection');
    assert.match(result.stderr, /timed out waiting for another Phantom installer/);
    assert.ok(Date.now() - started < 15000, 'the lock wait must stay bounded');
    assert.doesNotMatch(result.stdout, /downloading|checksum|installed to/);
    assert.equal(existsSync(curlLog), false, 'an unwritable staging parent must fail before any download');
    assertDestinationUnchanged(install, parent);
    assert.deepEqual(readdirSync(home), [], 'HOME must contain no leftover files');
  });

  test(`${label} installer surfaces the OS diagnostic when mktemp cannot write its staging directory`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), `phantom-unwritable-tempdir-${label}-`)));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const home = join(root, 'home');
    const shims = join(root, 'shims');
    const parent = join(root, 'live');
    const install = join(parent, 'bin');
    const curlLog = join(root, 'curl.log');
    const attempts = join(root, 'mktemp-attempts');
    mkdirSync(home);
    mkdirSync(shims);
    mkdirSync(install, { recursive: true });
    writeFileSync(join(install, 'old-install'), 'preserve-me');
    const realMktemp = execFileSync('which', ['mktemp'], { encoding: 'utf8' }).trim();
    // The parent stays writable so the lock is acquired; mktemp then reports
    // the same diagnostic the OS gives for an unwritable template directory.
    writeFileSync(join(shims, 'mktemp'), `#!/bin/sh
for arg do
  case "$arg" in
    *.install.XXXXXX)
      printf '%s\\n' "$arg" >> "$PHANTOM_TEST_MKTEMP_ATTEMPTS"
      printf "mktemp: failed to create directory via template '%s': Permission denied\\n" "$arg" >&2
      exit 1
      ;;
  esac
done
exec ${JSON.stringify(realMktemp)} "$@"
`);
    chmodSync(join(shims, 'mktemp'), 0o755);
    curlShim(shims);

    const result = spawnSync('/bin/bash', [installer], {
      encoding: 'utf8',
      timeout: 30000,
      env: {
        PATH: `${shims}:${process.env.PATH}`,
        HOME: home,
        SHELL: '/bin/bash',
        PHANTOM_INSTALL_DIR: install,
        PHANTOM_TEST_CURL_LOG: curlLog,
        PHANTOM_TEST_MKTEMP_ATTEMPTS: attempts,
      },
    });

    assert.ifError(result.error);
    assert.equal(result.status, 1, result.stderr);
    assert.deepEqual(readFileSync(attempts, 'utf8').trim().split('\n'), [
      join(parent, '.bin.install.XXXXXX'),
    ], 'mktemp must be asked only for the private sibling staging template');
    assert.match(result.stderr, /Permission denied/, 'the underlying OS diagnostic stays visible');
    assert.match(result.stderr, new RegExp(
      `could not create a private staging directory in ${escapeRegExp(parent)}`,
    ));
    assert.doesNotMatch(result.stdout, /downloading|checksum|installed to/);
    assert.equal(existsSync(curlLog), false, 'staging failure must precede any download');
    assertDestinationUnchanged(install, parent);
    assert.deepEqual(readdirSync(home), [], 'HOME must contain no leftover files');
  });

  test(`${label} installer exits nonzero and creates nothing when the install parent cannot be created`, {
    skip: isRoot && 'root ignores directory permissions',
  }, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), `phantom-unwritable-tempdir-${label}-`)));
    const home = join(root, 'home');
    const shims = join(root, 'shims');
    const sealed = join(root, 'sealed');
    const parent = join(sealed, 'missing');
    const install = join(parent, 'bin');
    const curlLog = join(root, 'curl.log');
    mkdirSync(home);
    mkdirSync(shims);
    mkdirSync(sealed);
    curlShim(shims);
    chmodSync(sealed, 0o555);
    t.after(() => {
      chmodSync(sealed, 0o755);
      rmSync(root, { recursive: true, force: true });
    });

    const result = spawnSync('/bin/bash', [installer], {
      encoding: 'utf8',
      timeout: 30000,
      env: {
        PATH: `${shims}:${process.env.PATH}`,
        HOME: home,
        SHELL: '/bin/bash',
        PHANTOM_INSTALL_DIR: install,
        PHANTOM_TEST_CURL_LOG: curlLog,
      },
    });

    assert.ifError(result.error);
    assert.notEqual(result.status, 0, result.stderr);
    assert.match(result.stderr, /Permission denied/i);
    // BSD mkdir names the requested parent; GNU mkdir -p can name the
    // existing sealed ancestor it tried to traverse. Bind the path to the
    // same Permission denied diagnostic, rather than accepting any error.
    assert.ok(permissionDiagnostic(result.stderr, [sealed, parent]),
      'the permission diagnostic must name the exact requested parent or its sealed ancestor');
    assert.doesNotMatch(result.stdout, /downloading|checksum|installed to/);
    assert.equal(existsSync(curlLog), false, 'an uncreatable parent must fail before the network');
    assert.equal(existsSync(install), false, 'the destination must not appear');
    assert.deepEqual(readdirSync(sealed), [], 'the unwritable directory stays empty');
    assert.deepEqual(readdirSync(home), [], 'HOME must contain no leftover files');
  });
}
