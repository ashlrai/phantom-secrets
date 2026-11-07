import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  accessSync,
  chmodSync,
  constants,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

// Both the repository installer and the copy served from the website must leave
// runnable binaries behind, even when the release archive ships them without
// the execute bit (mode 0600 here). Binaries are stubs; nothing is downloaded.
const installers = {
  'scripts/install.sh': new URL('install.sh', import.meta.url),
  'apps/web/public/install.sh': new URL('../apps/web/public/install.sh', import.meta.url),
};

for (const [label, url] of Object.entries(installers)) {
  test(`${label} installs executable binaries from a stubbed archive`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-installer-exec-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const fixture = join(root, 'fixture');
    const payload = join(root, 'payload');
    const home = join(root, 'home');
    const install = join(root, 'live', 'bin');
    for (const dir of [fixture, payload, home]) mkdirSync(dir, { recursive: true });
    for (const name of ['phantom', 'phantom-mcp']) {
      writeFileSync(join(payload, name), `#!/bin/sh\necho "${name} 1.2.3"\n`);
      chmodSync(join(payload, name), 0o600);
    }
    const os = { darwin: 'apple-darwin', linux: 'unknown-linux-gnu' }[process.platform];
    const arch = { x64: 'x86_64', arm64: 'aarch64' }[process.arch];
    assert.ok(os && arch, 'test requires a supported Unix installer target');
    const archive = `phantom-${arch}-${os}.tar.gz`;
    execFileSync('tar', ['-czf', join(fixture, archive), '-C', payload, 'phantom', 'phantom-mcp']);
    const digest = createHash('sha256').update(readFileSync(join(fixture, archive))).digest('hex');
    writeFileSync(join(fixture, `${archive}.sha256`), `${digest}  ${archive}\n`);

    const env = { ...process.env };
    for (const name of ['PHANTOM_REPO', 'PHANTOM_TEST_FAIL_AFTER_PROMOTION',
      'PHANTOM_INSTALL_LOCK_WAIT_SECONDS', 'PHANTOM_INSTALL_LOCK_STALE_SECONDS',
      'PHANTOM_INSTALL_LOCK_HEARTBEAT_SECONDS']) delete env[name];
    const result = spawnSync('/bin/bash', [fileURLToPath(url)], {
      encoding: 'utf8',
      timeout: 30000,
      env: {
        ...env,
        HOME: home,
        PATH: `${install}:${env.PATH}`,
        PHANTOM_INSTALL_DIR: install,
        PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
        PHANTOM_TEST_LOCAL_RELEASE_DIR: fixture,
        PHANTOM_TAG: 'v1.2.3',
      },
    });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);

    for (const name of ['phantom', 'phantom-mcp']) {
      const path = join(install, name);
      accessSync(path, constants.X_OK);
      assert.equal(statSync(path).mode & 0o777, 0o755, `${name} mode`);
      const run = spawnSync(path, ['--version'], { encoding: 'utf8' });
      assert.equal(run.stdout.trim(), `${name} 1.2.3`, `${name} runs`);
    }
  });
}
