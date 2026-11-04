import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

// The latest failure point: the new release is already promoted into the live
// directory when the gated fault fires. The exit trap must report the failure,
// move the failed install aside, restore the previous install, and delete the
// whole staging tree (including the failed install and the lock).
test('repository installer rolls back and removes staging after a post-promotion failure', (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-promotion-failure-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const fixture = join(root, 'fixture');
  const payload = join(root, 'payload');
  const home = join(root, 'home');
  const shims = join(root, 'shims');
  const install = join(root, 'live', 'bin');
  for (const dir of [fixture, payload, home, shims, install]) mkdirSync(dir, { recursive: true });
  writeFileSync(join(install, 'old-install'), 'preserve-me');
  for (const name of ['phantom', 'phantom-mcp']) {
    writeFileSync(join(payload, name), `#!/bin/bash\necho "${name} 1.2.3"\n`);
    chmodSync(join(payload, name), 0o755);
  }
  const os = { darwin: 'apple-darwin', linux: 'unknown-linux-gnu' }[process.platform];
  const arch = { x64: 'x86_64', arm64: 'aarch64' }[process.arch];
  assert.ok(os && arch, 'test requires a supported Unix installer target');
  const archive = `phantom-${arch}-${os}.tar.gz`;
  const archivePath = join(fixture, archive);
  execFileSync('tar', ['-czf', archivePath, '-C', payload, 'phantom', 'phantom-mcp']);
  const digest = createHash('sha256').update(readFileSync(archivePath)).digest('hex');
  writeFileSync(`${archivePath}.sha256`, `${digest}  ${archive}\n`);

  // Record the promotion move so the rollback assertions cannot pass
  // vacuously on an install that never reached the promoted state.
  const record = join(root, 'promoted');
  const realMv = execFileSync('which', ['mv'], { encoding: 'utf8' }).trim();
  writeFileSync(join(shims, 'mv'), `#!/bin/bash
if [ "$#" -eq 2 ] && [ "$2" = ${JSON.stringify(install)} ]; then
  printf '%s\\n' "$1" >> ${JSON.stringify(record)}
fi
exec ${JSON.stringify(realMv)} "$@"
`);
  chmodSync(join(shims, 'mv'), 0o755);

  const env = { ...process.env };
  for (const name of ['PHANTOM_REPO', 'PHANTOM_INSTALL_LOCK_WAIT_SECONDS',
    'PHANTOM_INSTALL_LOCK_STALE_SECONDS', 'PHANTOM_INSTALL_LOCK_HEARTBEAT_SECONDS']) delete env[name];
  const result = spawnSync('/bin/bash', [fileURLToPath(new URL('install.sh', import.meta.url))], {
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
      PHANTOM_TEST_FAIL_AFTER_PROMOTION: '1',
    },
  });
  assert.ifError(result.error);
  assert.ok(Number.isInteger(result.status) && result.status !== 0, 'installer exits nonzero');
  assert.match(result.stderr, /test-only injected failure after promotion/);
  assert.doesNotMatch(result.stdout, /installed to/);

  const promoted = readFileSync(record, 'utf8').trim().split('\n');
  assert.equal(promoted.length, 1, 'the candidate was promoted exactly once');
  assert.match(promoted[0], /\.bin\.install\.[^/]+\/candidate$/);
  assert.equal(existsSync(promoted[0]), false, 'candidate was moved into the live directory');

  assert.deepEqual(readdirSync(join(root, 'live')), ['bin'], 'staging, backup and lock are removed');
  assert.deepEqual(readdirSync(install), ['old-install'], 'failed install is rolled back');
  assert.equal(readFileSync(join(install, 'old-install'), 'utf8'), 'preserve-me');
  assert.deepEqual(readdirSync(home), [], 'HOME must contain no temporary files');
});
