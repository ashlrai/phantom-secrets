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
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

// A successful install promotes the candidate and must then remove the whole
// staging tree (including the displaced previous install) and the lock, so the
// install directory's parent holds only the installed `bin`.
for (const installer of ['install.sh', '../apps/web/public/install.sh']) {
test(`${installer} preserves an existing PATH entry during installation`, (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-installer-staging-success-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const fixture = join(root, 'fixture');
  const payload = join(root, 'payload');
  const home = join(root, 'home');
  const install = join(root, 'live', 'bin');
  for (const dir of [fixture, payload, home, install]) mkdirSync(dir, { recursive: true });
  writeFileSync(join(install, 'old-install'), 'previous');
  const rc = join(home, '.bashrc');
  const originalRc = `# existing configuration\nexport PATH="${install}:$PATH"\n`;
  writeFileSync(rc, originalRc);
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
      SHELL: '/bin/bash',
      // Already on PATH, so the installer does not touch shell rc files.
      PATH: `/usr/local/bin:${install}:/usr/bin:/bin`,
      PHANTOM_INSTALL_DIR: install,
      PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
      PHANTOM_TEST_LOCAL_RELEASE_DIR: fixture,
      PHANTOM_TAG: 'v1.2.3',
    },
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /installed to /);

  for (const name of ['phantom', 'phantom-mcp']) {
    assert.ok(existsSync(join(install, name)), `${name} is installed`);
  }
  assert.equal(existsSync(join(install, 'old-install')), false, 'previous install is replaced');
  assert.deepEqual(readdirSync(dirname(install)), ['bin'], 'no staging, backup, or lock beside install');
  assert.deepEqual(readdirSync(home), ['.bashrc'], 'HOME must contain no temporary files');
  assert.equal(readFileSync(rc, 'utf8'), originalRc, 'existing PATH configuration is unchanged');
  const shell = spawnSync('/bin/bash', ['--noprofile', '--norc', '-c',
    '. "$HOME/.bashrc"; printf %s "$PATH"'], {
    encoding: 'utf8',
    env: { HOME: home, PATH: '/usr/local/bin:/usr/bin:/bin' },
  });
  assert.ifError(shell.error);
  assert.equal(shell.status, 0);
  assert.deepEqual(shell.stdout.split(':'), [install, '/usr/local/bin', '/usr/bin', '/bin'],
    'sourcing the unchanged startup file adds the install directory once and preserves other entries');
});
}
