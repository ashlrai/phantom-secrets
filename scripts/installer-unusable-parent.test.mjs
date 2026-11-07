import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  chmodSync, mkdirSync, mkdtempSync, readdirSync, realpathSync, rmSync, writeFileSync,
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

function run(installer, installDir, home) {
  return spawnSync('/bin/bash', [installer], {
    encoding: 'utf8',
    timeout: 30000,
    env: { PATH: process.env.PATH, HOME: home, SHELL: '/bin/bash', PHANTOM_INSTALL_DIR: installDir,
      // An unwritable parent can never take the lock; keep the bounded wait short.
      PHANTOM_INSTALL_LOCK_WAIT_SECONDS: '1',
    },
  });
}

for (const [label, installer] of installers) {
  test(`${label} installer exits nonzero and leaves no staging when the install parent is read-only`, {
    skip: isRoot && 'root ignores directory permissions',
  }, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), `phantom-unusable-parent-${label}-`)));
    const parent = join(root, 'parent');
    const home = join(root, 'home');
    mkdirSync(parent);
    mkdirSync(home);
    chmodSync(parent, 0o555);
    t.after(() => {
      chmodSync(parent, 0o755);
      rmSync(root, { recursive: true, force: true });
    });

    const started = Date.now();
    const result = run(installer, join(parent, 'bin'), home);

    assert.ifError(result.error);
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stderr, /timed out waiting for another Phantom installer/);
    assert.ok(Date.now() - started < 10000, 'the lock wait must stay bounded');
    assert.doesNotMatch(result.stdout, /downloading|checksum/);
    assert.deepEqual(readdirSync(parent), [], 'no stage or lock directory may remain');
    assert.deepEqual(readdirSync(home), []);
  });

  test(`${label} installer exits nonzero and leaves no staging when the install parent is a file`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), `phantom-unusable-parent-${label}-`)));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const parentFile = join(root, 'parent-file');
    writeFileSync(parentFile, 'not a directory');

    const result = run(installer, join(parentFile, 'bin'), join(root, 'home'));

    assert.ifError(result.error);
    assert.notEqual(result.status, 0);
    assert.deepEqual(readdirSync(root).sort(), ['parent-file']);
  });
}
