import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  chmodSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

// Listing and inspecting the archive succeed; only extraction (-x) fails.
test('public installer leaves an existing executable untouched when extraction fails', () => {
  const root = mkdtempSync(join(tmpdir(), 'phantom-public-extract-'));
  try {
    const fixture = join(root, 'fixture');
    const payload = join(root, 'payload');
    const home = join(root, 'home');
    const stubs = join(root, 'stubs');
    const install = join(root, 'live', 'bin');
    for (const dir of [fixture, payload, home, stubs, install]) mkdirSync(dir, { recursive: true });
    const existing = '#!/bin/sh\necho old-phantom\n';
    writeFileSync(join(install, 'phantom'), existing);
    chmodSync(join(install, 'phantom'), 0o755);
    const before = statSync(join(install, 'phantom'));

    for (const name of ['phantom', 'phantom-mcp']) writeFileSync(join(payload, name), 'fixture');
    const os = { darwin: 'apple-darwin', linux: 'unknown-linux-gnu' }[process.platform];
    const arch = { x64: 'x86_64', arm64: 'aarch64' }[process.arch];
    assert.ok(os && arch, 'test requires a supported Unix installer target');
    const archive = `phantom-${arch}-${os}.tar.gz`;
    execFileSync('tar', ['-czf', join(fixture, archive), '-C', payload, 'phantom', 'phantom-mcp']);
    const digest = createHash('sha256').update(readFileSync(join(fixture, archive))).digest('hex');
    writeFileSync(join(fixture, `${archive}.sha256`), `${digest}  ${archive}\n`);

    const realTar = execFileSync('/bin/sh', ['-c', 'command -v tar'], { encoding: 'utf8' }).trim();
    writeFileSync(join(stubs, 'tar'), [
      '#!/bin/sh',
      'for arg; do',
      '  case "$arg" in',
      '    -xzf) echo "stub tar: extraction failed" >&2; exit 2 ;;',
      '  esac',
      'done',
      `exec "${realTar}" "$@"`,
      '',
    ].join('\n'));
    chmodSync(join(stubs, 'tar'), 0o755);

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
        PATH: `${stubs}:${process.env.PATH}`,
        PHANTOM_INSTALL_DIR: install,
        PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
        PHANTOM_TEST_LOCAL_RELEASE_DIR: fixture,
        PHANTOM_TAG: 'v1.2.3',
      },
    });
    assert.ifError(result.error);
    assert.notEqual(result.status, 0);
    assert.match(result.stdout, /checksum verified/, 'failure must come after checksum verification');
    assert.match(result.stderr, /could not extract release archive/);

    const after = statSync(join(install, 'phantom'));
    assert.equal(readFileSync(join(install, 'phantom'), 'utf8'), existing);
    assert.equal(after.mode & 0o777, 0o755);
    assert.equal(after.ino, before.ino, 'existing executable was not replaced');
    assert.deepEqual(readdirSync(install), ['phantom'], 'no partial files in the live directory');
    assert.deepEqual(readdirSync(join(root, 'live')), ['bin'], 'stage and lock are removed');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
