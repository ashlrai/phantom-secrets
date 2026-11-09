import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const installers = {
  repository: fileURLToPath(new URL('install.sh', import.meta.url)),
  public: fileURLToPath(new URL('../apps/web/public/install.sh', import.meta.url)),
};

for (const [name, installer] of Object.entries(installers)) {
  test(`${name} installer preserves the destination when staging creation fails`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-stage-failure-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const home = join(root, 'home');
    const shims = join(root, 'shims');
    const parent = join(root, 'live');
    const install = join(parent, 'bin');
    for (const dir of [home, shims, install]) mkdirSync(dir, { recursive: true });
    const sentinel = join(install, 'sentinel');
    writeFileSync(sentinel, 'existing installation\n');
    const calls = join(root, 'mktemp-calls');
    writeFileSync(join(shims, 'mktemp'), `#!/bin/sh\nprintf '%s\\n' "$@" > ${JSON.stringify(calls)}\nexit 1\n`);
    chmodSync(join(shims, 'mktemp'), 0o755);

    const result = spawnSync('/bin/bash', [installer], {
      encoding: 'utf8',
      timeout: 30000,
      env: {
        HOME: home,
        PATH: `${shims}:/usr/bin:/bin:/usr/sbin:/sbin`,
        PHANTOM_INSTALL_DIR: install,
      },
    });
    assert.ifError(result.error);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /could not create a private staging directory/);
    assert.deepEqual(readFileSync(calls, 'utf8').trimEnd().split('\n'), [
      '-d', join(parent, '.bin.install.XXXXXX'),
    ]);
    assert.equal(readFileSync(sentinel, 'utf8'), 'existing installation\n');
    assert.deepEqual(readdirSync(install), ['sentinel']);
    assert.deepEqual(readdirSync(parent), ['bin'], 'the install lock is released');
    assert.deepEqual(readdirSync(home), []);
  });
}
