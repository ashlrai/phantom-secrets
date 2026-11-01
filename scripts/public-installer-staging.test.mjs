import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

test('public installer cleans staging after an offline checksum mismatch', () => {
  const root = mkdtempSync(join(tmpdir(), 'phantom-public-stage-'));
  try {
    const fixture = join(root, 'fixture');
    const payload = join(root, 'payload');
    const home = join(root, 'home');
    const install = join(root, 'live', 'bin');
    for (const dir of [fixture, payload, home, install]) mkdirSync(dir, { recursive: true });
    writeFileSync(join(install, 'old-install'), 'preserve-me');
    for (const name of ['phantom', 'phantom-mcp']) writeFileSync(join(payload, name), 'fixture');
    const os = { darwin: 'apple-darwin', linux: 'unknown-linux-gnu' }[process.platform];
    const arch = { x64: 'x86_64', arm64: 'aarch64' }[process.arch];
    assert.ok(os && arch, 'test requires a supported Unix installer target');
    const archive = `phantom-${arch}-${os}.tar.gz`;
    execFileSync('tar', ['-czf', join(fixture, archive), '-C', payload, 'phantom', 'phantom-mcp']);
    writeFileSync(join(fixture, `${archive}.sha256`), `${'0'.repeat(64)}  ${archive}\n`);
    const env = { ...process.env };
    for (const name of ['PHANTOM_REPO', 'PHANTOM_TEST_FAIL_AFTER_PROMOTION',
      'PHANTOM_INSTALL_LOCK_WAIT_SECONDS', 'PHANTOM_INSTALL_LOCK_STALE_SECONDS',
      'PHANTOM_INSTALL_LOCK_HEARTBEAT_SECONDS']) delete env[name];
    const result = spawnSync('/bin/bash', [fileURLToPath(new URL('../apps/web/public/install.sh', import.meta.url))], {
      encoding: 'utf8',
      timeout: 30000,
      env: {
        ...env,
        HOME: home,
        PHANTOM_INSTALL_DIR: install,
        PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
        PHANTOM_TEST_LOCAL_RELEASE_DIR: fixture,
        PHANTOM_TAG: 'v1.2.3',
      },
    });
    assert.ifError(result.error);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /SHA-256 mismatch/);
    assert.equal(readFileSync(join(install, 'old-install'), 'utf8'), 'preserve-me');
    assert.deepEqual(readdirSync(join(root, 'live')), ['bin'], 'stage and lock are removed');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
