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
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

// A stubbed successful install with TMPDIR pointing at a path containing
// spaces must succeed, stage beside the install, and leave
// neither the staging directory nor unrelated files in the spaced TMPDIR behind.
for (const [name, installer, stageInTmp] of [
  ['repository', 'install.sh', false],
  ['public', '../apps/web/public/install.sh', true],
]) test(`${name} installer succeeds with a space-containing TMPDIR and cleans staging`, (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-installer-tmpdir-spaces-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const fixture = join(root, 'fixture');
  const payload = join(root, 'payload');
  const shims = join(root, 'shims');
  const mktempLog = join(root, 'mktemp.log');
  const home = join(root, 'home');
  const spacedTmp = join(root, 'tmp dir with spaces');
  const install = join(stageInTmp ? spacedTmp : root, 'live', 'bin');
  for (const dir of [fixture, payload, shims, home, spacedTmp, install]) mkdirSync(dir, { recursive: true });
  const realMktemp = execFileSync('which', ['mktemp'], { encoding: 'utf8' }).trim();
  writeFileSync(join(shims, 'mktemp'), `#!/bin/sh\nprintf '%s\\n' "$#" "$@" > "$MK_TEMP_LOG"\nexec ${JSON.stringify(realMktemp)} "$@"\n`);
  chmodSync(join(shims, 'mktemp'), 0o755);
  writeFileSync(join(install, 'old-install'), 'previous');
  for (const name of ['phantom', 'phantom-mcp']) {
    writeFileSync(join(payload, name), `#!/bin/sh\necho "${name} 1.2.3"\n`);
    chmodSync(join(payload, name), 0o755);
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
  const result = spawnSync('/bin/bash', [fileURLToPath(new URL(installer, import.meta.url))], {
    encoding: 'utf8',
    timeout: 30000,
    env: {
      ...env,
      HOME: home,
      TMPDIR: spacedTmp,
      // Already on PATH, so the installer does not touch shell rc files.
      PATH: `${shims}:${install}:${env.PATH}`,
      MK_TEMP_LOG: mktempLog,
      PHANTOM_INSTALL_DIR: install,
      PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
      PHANTOM_TEST_LOCAL_RELEASE_DIR: fixture,
      PHANTOM_TAG: 'v1.2.3',
    },
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /installed to /);
  assert.deepEqual(readFileSync(mktempLog, 'utf8').trim().split('\n'),
    ['2', '-d', join(dirname(install), '.bin.install.XXXXXX')],
    'mktemp receives the complete staging template as one argument');
  for (const name of ['phantom', 'phantom-mcp']) {
    assert.ok(existsSync(join(install, name)), `${name} is installed`);
  }
  assert.equal(existsSync(join(install, 'old-install')), false, 'previous install is replaced');
  assert.deepEqual(readdirSync(dirname(install)), ['bin'], 'no staging, backup, or lock beside install');
  assert.deepEqual(readdirSync(spacedTmp), stageInTmp ? ['live'] : [], 'TMPDIR contains only the intended install');
  assert.deepEqual(readdirSync(home), [], 'HOME must contain no temporary files');
});
