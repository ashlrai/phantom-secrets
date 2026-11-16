import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, lstatSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const copies = {
  'scripts/install.sh': resolve(import.meta.dirname, 'install.sh'),
  'apps/web/public/install.sh': resolve(import.meta.dirname, '..', 'apps', 'web', 'public', 'install.sh'),
};
const installer = readFileSync(copies['scripts/install.sh'], 'utf8');
const publicInstaller = readFileSync(copies['apps/web/public/install.sh'], 'utf8');

function pathUpdateFunction(source, file) {
  const start = source.indexOf('add_to_user_path() {\n');
  const end = source.indexOf('\n}\n\ncommand -v curl', start);
  assert.ok(start >= 0 && end > start, `${file}: locate the installer PATH-update function`);
  return source.slice(start, end + '\n}'.length);
}

const pathUpdate = pathUpdateFunction(installer, 'scripts/install.sh');

for (const failedTemp of ['before', 'candidate']) {
  test(`PATH update fails safely when ${failedTemp} temporary-file creation fails`, (t) => {
    const root = mkdtempSync(join(tmpdir(), 'phantom-path-temp-failure-'));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const home = join(root, 'home');
    const shims = join(root, 'shims');
    const rc = join(home, '.bashrc');
    const attempts = join(root, 'attempts');
    mkdirSync(home);
    mkdirSync(shims);
    const original = Buffer.from('# existing configuration\nexport EXAMPLE=unchanged\n');
    writeFileSync(rc, original, { mode: 0o600 });
    const before = lstatSync(rc);
    const shim = join(shims, 'mktemp');
    writeFileSync(shim, `#!/bin/sh
case "$1" in
  *.phantom-path.before.*) echo before >> "$TEST_ATTEMPTS" ;;
  *.phantom-path.candidate.*) echo candidate >> "$TEST_ATTEMPTS" ;;
  *) exit 2 ;;
esac
case "$1" in *.phantom-path.$TEST_FAIL_TEMP.*) exit 1 ;; esac
exec /usr/bin/mktemp "$@"
`);
    chmodSync(shim, 0o755);

    const result = spawnSync('/bin/bash', ['-c', `${pathUpdate}\nadd_to_user_path "$1"`, 'path-test', join(root, 'bin')], {
      encoding: 'utf8',
      env: { HOME: home, SHELL: '/bin/bash', PATH: `${shims}:/usr/bin:/bin`, TEST_ATTEMPTS: attempts, TEST_FAIL_TEMP: failedTemp },
    });
    assert.ifError(result.error);
    assert.equal(result.status, 1, 'PATH update must report failure');
    assert.equal(result.stderr, '', 'failure must be handled without later shell errors');
    assert.deepEqual(readFileSync(attempts, 'utf8').trim().split('\n'),
      failedTemp === 'before' ? ['before'] : ['before', 'candidate']);
    assert.deepEqual(readFileSync(rc), original);
    const after = lstatSync(rc);
    assert.equal(after.ino, before.ino, 'the startup file must not be replaced');
    assert.equal(after.mode, before.mode);
    assert.deepEqual(readdirSync(home), ['.bashrc'], 'temporary siblings must be removed');
  });
}

// A failed before-file creation must abort the update outright; a failed
// candidate-file creation must first remove the already-created before file
// and then abort. Both installer copies must carry those guards.
function creationGuard(body, kind, file) {
  const creations = [...body.matchAll(
    new RegExp(`^\\s*${kind}_tmp="\\$\\(mktemp "([^"\\n]+)"\\)"`, 'gm'),
  )];
  assert.equal(creations.length, 1, `${file}: expected one ${kind} temporary-file creation`);
  assert.equal(
    creations[0][1],
    `$rc_parent/.phantom-path.${kind}.XXXXXX`,
    `${file}: the ${kind} file must be a private sibling of the startup file`,
  );
  const tail = body.slice(creations[0].index + creations[0][0].length);
  if (kind === 'before') {
    assert.match(
      tail,
      /^[ \t]*\|\|[ \t]*return 1[ \t]*\n/,
      `${file}: a failed before-file creation must abort the PATH update`,
    );
  } else {
    assert.match(
      tail,
      /^[ \t]*\\[ \t]*\n[ \t]*\|\|[ \t]*\{[ \t]*rm -f -- "\$before_tmp";[ \t]*return 1;[ \t]*\}[ \t]*\n/,
      `${file}: a failed candidate-file creation must remove the before file and abort`,
    );
  }
  return creations[0].index;
}

for (const [file, source] of [
  ['scripts/install.sh', installer],
  ['apps/web/public/install.sh', publicInstaller],
]) {
  test(`${file} checks creation of the before and candidate temporary files`, () => {
    const body = pathUpdateFunction(source, file);
    const beforeIndex = creationGuard(body, 'before', file);
    const candidateIndex = creationGuard(body, 'candidate', file);
    assert.ok(beforeIndex < candidateIndex, `${file}: the before file must be created first`);
  });
}

test('both installer copies carry the identical PATH-update function', () => {
  assert.equal(
    pathUpdate,
    pathUpdateFunction(publicInstaller, 'apps/web/public/install.sh'),
    'PATH-update temporary-file guards must match across installer copies',
  );
});

test('the creation-guard check rejects unguarded temporary-file creation', () => {
  const unguardedBefore = pathUpdate.replace('before.XXXXXX")" || return 1', 'before.XXXXXX")"');
  assert.throws(() => creationGuard(unguardedBefore, 'before', 'fixture'), /must abort/);
  const unguardedCandidate = pathUpdate.replace('|| { rm -f -- "$before_tmp"; return 1; }', '');
  assert.throws(() => creationGuard(unguardedCandidate, 'candidate', 'fixture'), /must remove the before file/);
});
