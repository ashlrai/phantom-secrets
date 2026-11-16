import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

for (const [label, url] of [
  ['repository', new URL('install.sh', import.meta.url)],
  ['public', new URL('../apps/web/public/install.sh', import.meta.url)],
]) {
  test(`${label} installer stops when staging mktemp fails`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-mktemp-failure-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const home = join(root, 'home');
    const shims = join(root, 'shims');
    const parent = join(root, 'live');
    const install = join(parent, 'bin');
    for (const dir of [home, shims, install]) mkdirSync(dir, { recursive: true });
    writeFileSync(join(install, 'phantom'), 'existing installation');
    const attempted = join(root, 'mktemp-called');
    const downloaded = join(root, 'curl-called');
    writeFileSync(join(shims, 'mktemp'), `#!/bin/sh\nprintf '%s\\n' "$@" > ${JSON.stringify(attempted)}\nexit 1\n`);
    writeFileSync(join(shims, 'curl'), `#!/bin/sh\ntouch ${JSON.stringify(downloaded)}\nexit 1\n`);
    for (const tool of ['mktemp', 'curl']) chmodSync(join(shims, tool), 0o755);

    const env = { ...process.env };
    for (const name of ['PHANTOM_REPO', 'PHANTOM_TEST_FAIL_AFTER_PROMOTION',
      'PHANTOM_TEST_LOCAL_RELEASE_DIR', 'PHANTOM_INSTALL_LOCK_WAIT_SECONDS',
      'PHANTOM_INSTALL_LOCK_STALE_SECONDS', 'PHANTOM_INSTALL_LOCK_HEARTBEAT_SECONDS']) delete env[name];
    const result = spawnSync('/bin/bash', [fileURLToPath(url)], {
      encoding: 'utf8', timeout: 30000,
      env: { ...env, HOME: home, PATH: `${shims}:${env.PATH}`, PHANTOM_INSTALL_DIR: install,
        PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1', PHANTOM_TAG: 'v1.2.3' },
    });
    assert.ifError(result.error);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /could not create a private staging directory/);
    assert.deepEqual(readFileSync(attempted, 'utf8').trim().split('\n'),
      ['-d', join(parent, '.bin.install.XXXXXX')]);
    assert.equal(existsSync(downloaded), false, 'download must not start');
    assert.deepEqual(readdirSync(parent), ['bin'], 'the install lock must be released');
    assert.deepEqual(readdirSync(install), ['phantom']);
    assert.equal(readFileSync(join(install, 'phantom'), 'utf8'), 'existing installation');
    assert.deepEqual(readdirSync(home), []);
  });
}
