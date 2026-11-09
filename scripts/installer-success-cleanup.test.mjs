import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, readFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { createStagingFixture, installHashRecorders } from './lib/installer-staging-fixture.mjs';

for (const [name, path] of Object.entries({
  repository: './install.sh',
  public: '../apps/web/public/install.sh',
})) {
  test(`${name} installer removes populated staging after a successful first install`, (t) => {
    const { root, fixture, shims, archive } = createStagingFixture(t, 'phantom-success-cleanup-');
    const hashLog = installHashRecorders(root, shims);
    const home = join(root, 'home');
    const install = join(root, 'live', 'bin');
    mkdirSync(home);
    const env = { ...process.env };
    for (const key of ['PHANTOM_REPO', 'PHANTOM_TEST_FAIL_AFTER_PROMOTION',
      'PHANTOM_INSTALL_LOCK_WAIT_SECONDS', 'PHANTOM_INSTALL_LOCK_STALE_SECONDS',
      'PHANTOM_INSTALL_LOCK_HEARTBEAT_SECONDS']) delete env[key];
    const result = spawnSync('/bin/bash', [fileURLToPath(new URL(path, import.meta.url))], {
      encoding: 'utf8', timeout: 30000,
      env: { ...env, HOME: home, SHELL: '/bin/bash', PATH: `${shims}:${env.PATH}`,
        PHANTOM_INSTALL_DIR: install, PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
        PHANTOM_TEST_LOCAL_RELEASE_DIR: fixture, PHANTOM_TAG: 'v1.2.3' },
    });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
    const hashed = readFileSync(hashLog, 'utf8').trim().split('\n');
    assert.equal(hashed.length, 1, 'the downloaded archive was hashed');
    assert.equal(basename(hashed[0]), archive);
    assert.equal(basename(dirname(hashed[0])), 'download');
    const stage = dirname(dirname(hashed[0]));
    assert.equal(dirname(stage), dirname(install));
    assert.match(basename(stage), /^\.bin\.install\.[^/]+$/);
    assert.equal(existsSync(stage), false, 'the populated staging directory is removed');
    assert.deepEqual(readdirSync(dirname(install)), ['bin'], 'no staging or lock remains');
    assert.deepEqual(readdirSync(install).sort(), ['.phantom-install-source.json', 'phantom', 'phantom-mcp']);
  });
}
