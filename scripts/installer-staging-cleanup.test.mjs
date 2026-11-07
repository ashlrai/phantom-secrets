import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
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
import { basename, dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

// A checksum failure stops the repository installer after the private
// staging directory has been created and populated with the downloaded
// archive and sidecar. The exit trap must still remove that exact staging
// tree, release the install lock, and leave the previous install untouched.
test('repository installer removes its staging directory after a simulated installation failure', (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-installer-staging-cleanup-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const fixture = join(root, 'fixture');
  const payload = join(root, 'payload');
  const home = join(root, 'home');
  const shims = join(root, 'shims');
  const install = join(root, 'live', 'bin');
  for (const dir of [fixture, payload, home, shims, install]) mkdirSync(dir, { recursive: true });
  writeFileSync(join(install, 'old-install'), 'preserve-me');
  for (const name of ['phantom', 'phantom-mcp']) writeFileSync(join(payload, name), 'fixture');
  const os = { darwin: 'apple-darwin', linux: 'unknown-linux-gnu' }[process.platform];
  const arch = { x64: 'x86_64', arm64: 'aarch64' }[process.arch];
  assert.ok(os && arch, 'test requires a supported Unix installer target');
  const archive = `phantom-${arch}-${os}.tar.gz`;
  execFileSync('tar', ['-czf', join(fixture, archive), '-C', payload, 'phantom', 'phantom-mcp']);
  writeFileSync(join(fixture, `${archive}.sha256`), `${'0'.repeat(64)}  ${archive}\n`);

  // The installer hashes the staged download inside its staging directory.
  // Recording that path proves the staging tree existed and was populated at
  // the moment of failure, so the cleanup assertion below cannot pass
  // vacuously on a staging directory that was never created.
  const record = join(root, 'hashed-paths');
  for (const tool of ['sha256sum', 'shasum']) {
    writeFileSync(join(shims, tool), `#!/usr/bin/env node
const { createHash } = require('node:crypto');
const { appendFileSync, readFileSync } = require('node:fs');
const target = process.argv.at(-1);
appendFileSync(${JSON.stringify(record)}, target + '\\n');
const digest = createHash('sha256').update(readFileSync(target)).digest('hex');
process.stdout.write(digest + '  ' + target + '\\n');
`);
    chmodSync(join(shims, tool), 0o755);
  }

  const env = { ...process.env };
  for (const name of ['PHANTOM_REPO', 'PHANTOM_TEST_FAIL_AFTER_PROMOTION',
    'PHANTOM_INSTALL_LOCK_WAIT_SECONDS', 'PHANTOM_INSTALL_LOCK_STALE_SECONDS',
    'PHANTOM_INSTALL_LOCK_HEARTBEAT_SECONDS']) delete env[name];
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
    },
  });
  assert.ifError(result.error);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /SHA-256 mismatch/);

  const hashed = readFileSync(record, 'utf8').trim().split('\n');
  assert.equal(hashed.length, 1, 'the staged download is hashed exactly once');
  const [staged] = hashed;
  assert.equal(basename(staged), archive);
  assert.equal(basename(dirname(staged)), 'download');
  const stageRoot = dirname(dirname(staged));
  assert.equal(dirname(stageRoot), dirname(install));
  assert.match(basename(stageRoot), /^\.bin\.install\.[^/]+$/);
  assert.equal(existsSync(stageRoot), false, 'staging directory must be removed');
  assert.deepEqual(readdirSync(dirname(install)), ['bin'], 'staging and lock are removed');
  assert.equal(readFileSync(join(install, 'old-install'), 'utf8'), 'preserve-me');
  assert.deepEqual(readdirSync(home), [], 'HOME must contain no temporary files');
});
