import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync,
  realpathSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const repo = resolve(import.meta.dirname, '..');
const installers = {
  repository: join(repo, 'scripts', 'install.sh'),
  public: join(repo, 'apps', 'web', 'public', 'install.sh'),
};

// Never executes a release binary: the offline fixture carries a deliberately
// wrong checksum, so the installer stops right after staging and downloading.
// That is enough to prove where staging lands for a parent containing spaces,
// on hosts that refuse to run stub binaries named `phantom`.
function fixture(root) {
  const os = { darwin: 'apple-darwin', linux: 'unknown-linux-gnu' }[process.platform];
  const arch = { x64: 'x86_64', arm64: 'aarch64' }[process.arch];
  assert.ok(os && arch, 'test requires a supported Unix installer target');
  const release = join(root, 'release');
  const payload = join(root, 'payload');
  mkdirSync(release);
  mkdirSync(payload);
  writeFileSync(join(payload, 'phantom'), 'x');
  writeFileSync(join(payload, 'phantom-mcp'), 'x');
  const archive = `phantom-${arch}-${os}.tar.gz`;
  execFileSync('tar', ['-czf', join(release, archive), '-C', payload, 'phantom', 'phantom-mcp']);
  writeFileSync(join(release, `${archive}.sha256`), `${'0'.repeat(64)}  ${archive}\n`);
  return release;
}

for (const [name, installer] of Object.entries(installers)) {
  test(`${name} installer stages as one path beneath a symlinked, not-yet-created spaced parent`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-spaced-offline-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const release = fixture(root);
    const home = join(root, 'home');
    const shims = join(root, 'shims');
    mkdirSync(home);
    mkdirSync(shims);

    // The spaced parent is reached through a symlink and does not exist yet.
    const real = join(root, 'real root');
    mkdirSync(real);
    symlinkSync(real, join(root, 'link root'));
    const install = join(root, 'link root', 'new parent', 'bin');
    const physicalParent = join(real, 'new parent');

    // Records each mktemp argv and the staging directory it created.
    const log = join(root, 'mktemp.log');
    const realMktemp = execFileSync('which', ['mktemp'], { encoding: 'utf8' }).trim();
    writeFileSync(join(shims, 'mktemp'), `#!/bin/sh
out="$(${JSON.stringify(realMktemp)} "$@")" || exit $?
printf '%s\\t%s\\n' "$*" "$out" >> ${JSON.stringify(log)}
printf '%s\\n' "$out"
`);
    chmodSync(join(shims, 'mktemp'), 0o755);

    const env = { ...process.env };
    for (const key of ['TMPDIR', 'PHANTOM_REPO', 'PHANTOM_TEST_FAIL_AFTER_PROMOTION']) delete env[key];
    const result = spawnSync('/bin/bash', [installer], {
      encoding: 'utf8',
      timeout: 30000,
      env: {
        ...env,
        HOME: home,
        SHELL: '/bin/bash',
        PATH: `${shims}:${env.PATH}`,
        PHANTOM_INSTALL_DIR: install,
        PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
        PHANTOM_TEST_LOCAL_RELEASE_DIR: release,
        PHANTOM_TAG: 'v1.2.3',
      },
    });
    assert.ifError(result.error);
    assert.notEqual(result.status, 0, 'the wrong checksum fails the install');
    assert.match(result.stderr, /SHA-256 mismatch/, 'the installer got past staging and download');

    const calls = readFileSync(log, 'utf8').split('\n').filter((l) => l.startsWith('-d '));
    assert.equal(calls.length, 1, 'exactly one staging directory was requested');
    const [template, created] = calls[0].split('\t');
    assert.equal(template, `-d ${join(physicalParent, '.bin.install.XXXXXX')}`,
      'the template is one path under the resolved spaced parent');
    assert.ok(created.startsWith(`${join(physicalParent, '.bin.install.')}`));
    assert.equal(existsSync(created), false, 'staging is removed after the failure');
    assert.deepEqual(readdirSync(physicalParent), [], 'no staging, backup, or lock left behind');
    assert.equal(existsSync(join(root, 'new parent')), false, 'the parent was not split at its space');
    assert.equal(existsSync(join(root, 'link')), false, 'nothing was created at a split prefix');
  });
}

for (const [name, installer] of Object.entries(installers)) {
  test(`${name} installer keeps an existing install and leaves no staging in a spaced parent`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-spaced-existing-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const release = fixture(root);
    const home = join(root, 'home');
    mkdirSync(home);
    const parent = join(root, 'my apps');
    const install = join(parent, 'bin');
    mkdirSync(install, { recursive: true });
    writeFileSync(join(install, 'phantom'), 'old-install');

    const env = { ...process.env };
    for (const key of ['TMPDIR', 'PHANTOM_REPO', 'PHANTOM_TEST_FAIL_AFTER_PROMOTION']) delete env[key];
    const result = spawnSync('/bin/bash', [installer], {
      encoding: 'utf8',
      timeout: 30000,
      env: {
        ...env,
        HOME: home,
        SHELL: '/bin/bash',
        PHANTOM_INSTALL_DIR: install,
        PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
        PHANTOM_TEST_LOCAL_RELEASE_DIR: release,
        PHANTOM_TAG: 'v1.2.3',
      },
    });
    assert.ifError(result.error);
    assert.notEqual(result.status, 0, 'the wrong checksum fails the install');
    assert.match(result.stderr, /SHA-256 mismatch/);
    assert.equal(readFileSync(join(install, 'phantom'), 'utf8'), 'old-install');
    assert.deepEqual(readdirSync(parent), ['bin'], 'no staging, backup, or lock left behind');
    assert.deepEqual(readdirSync(root).sort(), ['home', 'my apps', 'payload', 'release']);
  });
}
