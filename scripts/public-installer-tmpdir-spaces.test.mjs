import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

test('public installer preserves a spaced TMPDIR in its staging path', (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-tmpdir-test-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const temp = join(root, 'temporary directory with spaces');
  const home = join(temp, 'home');
  const fixture = join(root, 'fixture');
  const payload = join(root, 'payload');
  const shims = join(root, 'shims');
  for (const dir of [home, fixture, payload, shims]) mkdirSync(dir, { recursive: true });
  const os = { darwin: 'apple-darwin', linux: 'unknown-linux-gnu' }[process.platform];
  const arch = { x64: 'x86_64', arm64: 'aarch64' }[process.arch];
  assert.ok(os && arch, 'test requires a supported Unix installer target');
  const archive = `phantom-${arch}-${os}.tar.gz`;
  for (const name of ['phantom', 'phantom-mcp']) writeFileSync(join(payload, name), 'fixture');
  execFileSync('tar', ['-czf', join(fixture, archive), '-C', payload, 'phantom', 'phantom-mcp']);
  writeFileSync(join(fixture, `${archive}.sha256`), `${'0'.repeat(64)}  ${archive}\n`);
  const log = join(root, 'staging-args');
  const realMktemp = execFileSync('which', ['mktemp'], { encoding: 'utf8' }).trim();
  writeFileSync(join(shims, 'mktemp'), `#!/bin/sh\nif [ "$1" = -d ]; then printf '%s\\0' "$@" > "$STAGING_LOG"; fi\nexec ${JSON.stringify(realMktemp)} "$@"\n`, { mode: 0o755 });
  const result = spawnSync('/bin/bash', [fileURLToPath(new URL('../apps/web/public/install.sh', import.meta.url))], {
    encoding: 'utf8', timeout: 30000,
    env: { PATH: `${shims}:/usr/bin:/bin`, HOME: home, TMPDIR: temp, SHELL: '/bin/bash', STAGING_LOG: log,
      PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1', PHANTOM_TEST_LOCAL_RELEASE_DIR: fixture, PHANTOM_TAG: 'v1.2.3' },
  });
  assert.ifError(result.error);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /SHA-256 mismatch/);
  const args = readFileSync(log, 'utf8').split('\0');
  assert.deepEqual(args, ['-d', join(home, '.phantom-secrets', '.bin.install.XXXXXX'), '']);
  assert.equal(existsSync(join(root, 'temporary')), false, 'no word-split path was created');
  assert.deepEqual(readdirSync(join(home, '.phantom-secrets')), [], 'staging and lock were cleaned up');
});

