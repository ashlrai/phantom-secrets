import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

test('repository installer removes partial staging after extraction fails', (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-extraction-failure-')));
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
  const archivePath = join(fixture, archive);
  const realTar = execFileSync('which', ['tar'], { encoding: 'utf8' }).trim();
  execFileSync(realTar, ['-czf', archivePath, '-C', payload, 'phantom', 'phantom-mcp']);
  const digest = createHash('sha256').update(readFileSync(archivePath)).digest('hex');
  writeFileSync(`${archivePath}.sha256`, `${digest}  ${archive}\n`);

  // Let both archive inspections use real tar, then leave a partial file
  // and fail extraction. Record the actual candidate path to prove that
  // cleanup removes the staging directory that existed at the failure.
  const record = join(root, 'candidate-path');
  writeFileSync(join(shims, 'tar'), `#!/bin/bash
if [ "$1" = "--no-same-owner" ] && [ "$2" = "-xzf" ] && [ "$4" = "-C" ]; then
printf '%s\\n' "$5" > ${JSON.stringify(record)}
printf partial > "$5/phantom"
exit 42
fi
exec ${JSON.stringify(realTar)} "$@"
`);
  chmodSync(join(shims, 'tar'), 0o755);
  const env = { ...process.env };
  for (const name of ['PHANTOM_REPO', 'PHANTOM_TEST_FAIL_AFTER_PROMOTION',
    'PHANTOM_INSTALL_LOCK_WAIT_SECONDS', 'PHANTOM_INSTALL_LOCK_STALE_SECONDS',
    'PHANTOM_INSTALL_LOCK_HEARTBEAT_SECONDS']) delete env[name];
  const result = spawnSync('/bin/bash', [fileURLToPath(new URL('install.sh', import.meta.url))], {
    encoding: 'utf8', timeout: 30000,
    env: { ...env, HOME: home, PATH: `${shims}:${env.PATH}`, PHANTOM_INSTALL_DIR: install,
      PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1', PHANTOM_TEST_LOCAL_RELEASE_DIR: fixture,
      PHANTOM_TAG: 'v1.2.3' },
  });
  assert.ifError(result.error);
  assert.ok(Number.isInteger(result.status) && result.status !== 0, 'installer exits nonzero');
  assert.match(result.stderr, /could not extract release archive/);
  const candidate = readFileSync(record, 'utf8').trim();
  assert.equal(basename(candidate), 'candidate');
  const stageRoot = dirname(candidate);
  assert.equal(dirname(stageRoot), dirname(install));
  assert.match(basename(stageRoot), /^\.bin\.install\.[^/]+$/);
  assert.equal(existsSync(stageRoot), false, 'partial staging directory must be removed');
  assert.deepEqual(readdirSync(dirname(install)), ['bin'], 'staging and lock are removed');
  assert.deepEqual(readdirSync(install), ['old-install']);
  assert.equal(readFileSync(join(install, 'old-install'), 'utf8'), 'preserve-me');
  assert.deepEqual(readdirSync(home), [], 'HOME must contain no temporary files');
});
