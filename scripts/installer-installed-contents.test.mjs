import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
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

const TAG = '1.2.3';
const PROGRAMS = {
  phantom: `#!/bin/sh\necho "phantom ${TAG}"\n# known-program-marker: phantom\n`,
  'phantom-mcp': `#!/bin/sh\necho "phantom-mcp ${TAG}"\n# known-program-marker: phantom-mcp\n`,
};

function buildFixture(root, { sidecarDigest } = {}) {
  const fixture = join(root, 'fixture');
  const payload = join(root, 'payload');
  mkdirSync(fixture, { recursive: true });
  mkdirSync(payload, { recursive: true });
  for (const [name, body] of Object.entries(PROGRAMS)) {
    writeFileSync(join(payload, name), body);
    chmodSync(join(payload, name), 0o600); // installer must set the exec bit itself
  }
  const os = { darwin: 'apple-darwin', linux: 'unknown-linux-gnu' }[process.platform];
  const arch = { x64: 'x86_64', arm64: 'aarch64' }[process.arch];
  assert.ok(os && arch, 'test requires a supported Unix installer target');
  const archive = `phantom-${arch}-${os}.tar.gz`;
  execFileSync('tar', ['-czf', join(fixture, archive), '-C', payload, 'phantom', 'phantom-mcp']);
  const digest = sidecarDigest
    ?? createHash('sha256').update(readFileSync(join(fixture, archive))).digest('hex');
  writeFileSync(join(fixture, `${archive}.sha256`), `${digest}  ${archive}\n`);
  return { fixture, target: `${arch}-${os}` };
}

function runInstaller(root, fixture, install) {
  const home = join(root, 'home');
  mkdirSync(home, { recursive: true });
  const env = { ...process.env };
  for (const name of ['PHANTOM_REPO', 'PHANTOM_TEST_FAIL_AFTER_PROMOTION',
    'PHANTOM_INSTALL_LOCK_WAIT_SECONDS', 'PHANTOM_INSTALL_LOCK_STALE_SECONDS',
    'PHANTOM_INSTALL_LOCK_HEARTBEAT_SECONDS']) delete env[name];
  return spawnSync('/bin/bash', [fileURLToPath(new URL('install.sh', import.meta.url))], {
    encoding: 'utf8',
    timeout: 30000,
    env: {
      ...env,
      HOME: home,
      PATH: `${install}:${env.PATH}`, // already on PATH: rc files stay untouched
      PHANTOM_INSTALL_DIR: install,
      PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
      PHANTOM_TEST_LOCAL_RELEASE_DIR: fixture,
      PHANTOM_TAG: `v${TAG}`,
    },
  });
}

test('installer installs the stubbed archive programs with exact contents, modes, and receipt', (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-installer-contents-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const { fixture, target } = buildFixture(root);
  const install = join(root, 'live', 'bin');

  const result = runInstaller(root, fixture, install);
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);

  for (const [name, body] of Object.entries(PROGRAMS)) {
    const path = join(install, name);
    assert.equal(readFileSync(path, 'utf8'), body, `${name} contents match the archive byte for byte`);
    assert.equal(statSync(path).mode & 0o777, 0o755, `${name} is installed 0755`);
    const run = spawnSync(path, ['--version'], { encoding: 'utf8' });
    assert.equal(run.status, 0);
    assert.equal(run.stdout.trim(), `${name} ${TAG}`, `${name} runs as the known program`);
  }
  assert.deepEqual(readdirSync(install).sort(), ['.phantom-install-source.json', 'phantom', 'phantom-mcp']);
  assert.deepEqual(JSON.parse(readFileSync(join(install, '.phantom-install-source.json'), 'utf8')), {
    schema_version: 1,
    source: 'direct',
    version: TAG,
    target,
  });
});

test('installer installs nothing when the archive does not match its checksum', (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-installer-badsum-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const { fixture } = buildFixture(root, { sidecarDigest: '0'.repeat(64) });
  const install = join(root, 'live', 'bin');

  const result = runInstaller(root, fixture, install);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /SHA-256 mismatch/);
  assert.equal(existsSync(install), false, 'no install directory is created');
  assert.deepEqual(readdirSync(join(root, 'live')), [], 'no staging, backup, or lock is left behind');
});
