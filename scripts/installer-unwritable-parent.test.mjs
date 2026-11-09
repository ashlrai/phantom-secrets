import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, realpathSync, rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const repo = resolve(import.meta.dirname, '..');
const installers = [
  ['repository', join(repo, 'scripts', 'install.sh')],
  ['public', join(repo, 'apps', 'web', 'public', 'install.sh')],
];
// Permission bits do not bind root, so the fixture cannot be made unwritable.
const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;

for (const [label, installer] of installers) {
  test(`${label} installer exits nonzero without reporting success when the install parent is unwritable`, { skip: isRoot && 'root ignores directory permissions' }, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), `phantom-unwritable-parent-${label}-`)));
    const parent = join(root, 'readonly');
    const home = join(root, 'home');
    const install = join(parent, 'bin');
    mkdirSync(parent);
    mkdirSync(home);
    chmodSync(parent, 0o555);
    t.after(() => {
      chmodSync(parent, 0o755);
      rmSync(root, { recursive: true, force: true });
    });

    const env = { ...process.env };
    for (const name of [
      'PHANTOM_REPO', 'PHANTOM_TAG', 'PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES',
      'PHANTOM_TEST_LOCAL_RELEASE_DIR', 'PHANTOM_TEST_FAIL_AFTER_PROMOTION',
      'PHANTOM_INSTALL_LOCK_WAIT_SECONDS', 'PHANTOM_INSTALL_LOCK_STALE_SECONDS',
      'PHANTOM_INSTALL_LOCK_HEARTBEAT_SECONDS',
    ]) delete env[name];
    const started = Date.now();
    const result = spawnSync('/bin/bash', [installer], {
      encoding: 'utf8',
      timeout: 15000,
      env: {
        ...env, HOME: home, SHELL: '/bin/bash', PHANTOM_INSTALL_DIR: install,
        // An unwritable parent can never take the lock; keep the bounded wait short.
        PHANTOM_INSTALL_LOCK_WAIT_SECONDS: '1',
      },
    });

    assert.ifError(result.error);
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stderr, /✗.* phantom: /, 'the failure must be reported through die()');
    assert.doesNotMatch(result.stdout, /installed to|done\.|archive identity verified/);
    assert.doesNotMatch(result.stderr, /installed to|done\./);
    assert.doesNotMatch(result.stdout, /downloading|checksum/);
    assert.ok(Date.now() - started < 10000, 'the lock wait must stay bounded');
    assert.equal(existsSync(install), false);
    assert.deepEqual(readdirSync(parent), [], 'nothing may be left in the parent');
    assert.deepEqual(readdirSync(home), [], 'HOME must stay untouched');
  });
}
