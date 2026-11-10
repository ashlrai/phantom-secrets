import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { createStagingFixture } from './lib/installer-staging-fixture.mjs';

for (const [name, installer] of Object.entries({
  repository: new URL('install.sh', import.meta.url),
  public: new URL('../apps/web/public/install.sh', import.meta.url),
})) {
  test(`${name} installer stops before archive handling when staging creation fails`, (t) => {
    const { root, fixture, shims } = createStagingFixture(t, 'phantom-stage-create-failure-');
    const home = join(root, 'home');
    const install = join(root, 'live', 'bin');
    mkdirSync(home);
    mkdirSync(install, { recursive: true });
    writeFileSync(join(install, 'old-install'), 'preserve-me');
    const mktempLog = join(root, 'mktemp-called');
    const tarLog = join(root, 'tar-called');
    writeFileSync(join(shims, 'mktemp'), `#!/bin/sh\nprintf '%s\\n' "$@" > ${JSON.stringify(mktempLog)}\nexit 42\n`, { mode: 0o755 });
    writeFileSync(join(shims, 'tar'), `#!/bin/sh\nprintf called > ${JSON.stringify(tarLog)}\nexit 42\n`, { mode: 0o755 });
    const env = { ...process.env };
    for (const key of ['PHANTOM_REPO', 'PHANTOM_TEST_FAIL_AFTER_PROMOTION',
      'PHANTOM_INSTALL_LOCK_WAIT_SECONDS', 'PHANTOM_INSTALL_LOCK_STALE_SECONDS',
      'PHANTOM_INSTALL_LOCK_HEARTBEAT_SECONDS']) delete env[key];
    const result = spawnSync('/bin/bash', [fileURLToPath(installer)], {
      encoding: 'utf8', timeout: 30000,
      env: { ...env, HOME: home, PATH: `${shims}:${env.PATH}`, PHANTOM_INSTALL_DIR: install,
        PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1', PHANTOM_TEST_LOCAL_RELEASE_DIR: fixture,
        PHANTOM_TAG: 'v1.2.3' },
    });
    assert.ifError(result.error);
    assert.ok(Number.isInteger(result.status) && result.status !== 0, 'installer exits nonzero');
    assert.match(result.stderr, /could not create a private staging directory/);
    assert.deepEqual(readFileSync(mktempLog, 'utf8').trim().split('\n'),
      ['-d', join(dirname(install), '.bin.install.XXXXXX')]);
    assert.equal(existsSync(tarLog), false, 'archive inspection and extraction never start');
    assert.deepEqual(readdirSync(dirname(install)), ['bin'], 'lock and staging leave no leftovers');
    assert.deepEqual(readdirSync(install), ['old-install']);
    assert.equal(readFileSync(join(install, 'old-install'), 'utf8'), 'preserve-me');
    assert.deepEqual(readdirSync(home), []);
  });
}
