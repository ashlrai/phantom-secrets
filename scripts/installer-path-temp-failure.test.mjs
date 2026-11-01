import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, lstatSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const installer = readFileSync(resolve(import.meta.dirname, 'install.sh'), 'utf8');
const start = installer.indexOf('add_to_user_path() {\n');
const end = installer.indexOf('\n}\n\ncommand -v curl', start);
assert.ok(start >= 0 && end > start, 'locate the installer PATH-update function');
const pathUpdate = installer.slice(start, end + '\n}'.length);

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
