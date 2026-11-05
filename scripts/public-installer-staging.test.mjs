import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

test('public installer cleans staging after an offline checksum mismatch', () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-public-stage-')));
  try {
    const fixture = join(root, 'fixture');
    const payload = join(root, 'payload');
    const home = join(root, 'home');
    const parent = join(root, 'installation parent with spaces');
    const install = join(parent, 'bin');
    const shims = join(root, 'shims');
    const stageLog = join(root, 'stage.log');
    for (const dir of [fixture, payload, home, install, shims]) mkdirSync(dir, { recursive: true });
    writeFileSync(join(install, 'old-install'), 'preserve-me');
    for (const name of ['phantom', 'phantom-mcp']) writeFileSync(join(payload, name), 'fixture');
    const os = { darwin: 'apple-darwin', linux: 'unknown-linux-gnu' }[process.platform];
    const arch = { x64: 'x86_64', arm64: 'aarch64' }[process.arch];
    assert.ok(os && arch, 'test requires a supported Unix installer target');
    const archive = `phantom-${arch}-${os}.tar.gz`;
    execFileSync('tar', ['-czf', join(fixture, archive), '-C', payload, 'phantom', 'phantom-mcp']);
    writeFileSync(join(fixture, `${archive}.sha256`), `${'0'.repeat(64)}  ${archive}\n`);
    const mktemp = execFileSync('which', ['mktemp'], { encoding: 'utf8' }).trim();
    const shim = join(shims, 'mktemp');
    writeFileSync(shim, `#!/bin/sh\nstage="$(${JSON.stringify(mktemp)} "$@")" || exit $?\nif [ "$1" = -d ]; then printf '%s\\n' "$stage" >> ${JSON.stringify(stageLog)}; fi\nprintf '%s\\n' "$stage"\n`);
    chmodSync(shim, 0o755);
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
        PATH: `${shims}:${env.PATH}`,
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
    const stages = readFileSync(stageLog, 'utf8').trim().split('\n');
    assert.equal(stages.length, 1, 'one staging directory was created');
    assert.equal(dirname(stages[0]), parent, 'staging is beneath the spaced installation parent');
    assert.match(basename(stages[0]), /^\.bin\.install\./);
    assert.equal(existsSync(stages[0]), false, 'staging is removed');
    assert.deepEqual(readdirSync(parent), ['bin'], 'stage and lock are removed');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
