import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

// Re-running the public installer must never stack PATH entries. Unlike the
// function-level coverage in installer-path-idempotence.test.mjs, these tests
// execute the shipped script end to end (offline, through the test fixture
// seam), so both idempotence mechanisms are pinned where they actually run:
// the exact-PATH-entry gate in the caller and the marker short-circuit inside
// add_to_user_path. Each repeat is a real install — lock, staging, checksum,
// backup, promotion — so the assertions also prove the second run upgrades
// the binaries while leaving exactly one installer-managed PATH block.
const installer = fileURLToPath(new URL('../apps/web/public/install.sh', import.meta.url));
const marker = '# phantom-secrets PATH';
// A minimal PATH that cannot already contain the fresh temp install dir.
const BASE_PATH = '/usr/local/bin:/usr/bin:/bin';

const shells = {
  bash: {
    shell: '/bin/bash',
    rc: (home) => join(home, '.bashrc'),
    pathLine: (bin) => `export PATH="${bin}:$PATH"`,
  },
  zsh: {
    shell: '/bin/zsh',
    rc: (home) => join(home, '.zshrc'),
    pathLine: (bin) => `export PATH="${bin}:$PATH"`,
  },
  fish: {
    shell: '/usr/bin/fish',
    rc: (home) => join(home, '.config', 'fish', 'config.fish'),
    pathLine: (bin) => `set -gx PATH "${bin}" $PATH`,
  },
};

// An offline release for `version`: the two fixture binaries plus the
// checksum sidecar the installer verifies before promotion.
function buildFixture(root, version) {
  const fixture = join(root, `fixture-${version}`);
  const payload = join(root, `payload-${version}`);
  mkdirSync(fixture, { recursive: true });
  mkdirSync(payload, { recursive: true });
  for (const name of ['phantom', 'phantom-mcp']) {
    writeFileSync(join(payload, name),
      `#!/bin/sh\n[ "$1" = --version ] || exit 2\necho '${name} ${version}'\n`);
    chmodSync(join(payload, name), 0o755);
  }
  const os = { darwin: 'apple-darwin', linux: 'unknown-linux-gnu' }[process.platform];
  const arch = { x64: 'x86_64', arm64: 'aarch64' }[process.arch];
  assert.ok(os && arch, 'test requires a supported Unix installer target');
  const archive = `phantom-${arch}-${os}.tar.gz`;
  execFileSync('tar', ['-czf', join(fixture, archive), '-C', payload, 'phantom', 'phantom-mcp']);
  const digest = createHash('sha256').update(readFileSync(join(fixture, archive))).digest('hex');
  writeFileSync(join(fixture, `${archive}.sha256`), `${digest}  ${archive}\n`);
  return fixture;
}

// One full run of the shipped public installer against an offline fixture.
// `pathPrefix` simulates a PATH that already resolved through the rc file.
function runInstaller({ home, shell, install, fixture, tag, pathPrefix }) {
  const env = { ...process.env };
  for (const name of Object.keys(env)) {
    if (name.startsWith('PHANTOM_')) delete env[name];
  }
  const result = spawnSync('/bin/bash', [installer], {
    encoding: 'utf8',
    timeout: 30000,
    env: {
      ...env,
      HOME: home,
      SHELL: shell,
      PATH: pathPrefix ? `${pathPrefix}:${BASE_PATH}` : BASE_PATH,
      PHANTOM_INSTALL_DIR: install,
      PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
      PHANTOM_TEST_LOCAL_RELEASE_DIR: fixture,
      PHANTOM_TAG: tag,
    },
  });
  assert.ifError(result.error);
  return result;
}

// The startup file after every repeat must hold exactly one installer-managed
// block (one marker line, one PATH line), keep private permissions, keep any
// pre-existing user content, and leave no PATH-update temporary siblings.
function assertSingleManagedBlock(rc, config, install) {
  const lines = readFileSync(rc, 'utf8').split('\n');
  assert.equal(lines.filter((line) => line === marker).length, 1,
    'exactly one installer-managed PATH marker');
  assert.equal(lines.filter((line) => line === config.pathLine(install)).length, 1,
    'exactly one installer-managed PATH line');
  assert.equal(statSync(rc).mode & 0o777, 0o600,
    'the startup file keeps private permissions');
  assert.deepEqual(
    readdirSync(dirname(rc)).filter((name) => name.startsWith('.phantom-path.')),
    [],
    'no PATH-update temporary files are left behind',
  );
  return lines;
}

// Two full installer runs in one terminal (the resolved PATH never contains
// the install dir) must end with a single installer-managed PATH entry: the
// first run wires the rc file, the repeat reinstalls and short-circuits on
// the marker without rewriting the startup file.
for (const [shellName, config] of Object.entries(shells)) {
  for (const scenario of ['pre-existing', 'absent']) {
    test(`public installer keeps one ${shellName} PATH entry across two installs (${scenario} startup file)`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-public-path-rerun-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const install = join(root, 'live', 'bin');
      const rc = config.rc(home);
      if (scenario === 'pre-existing') {
        mkdirSync(dirname(rc), { recursive: true });
        writeFileSync(rc, '# user shell config\nexport EDITOR=vim\n', { mode: 0o600 });
      } else {
        mkdirSync(home, { recursive: true });
      }
      const fixtureA = buildFixture(root, '1.2.3');
      const fixtureB = buildFixture(root, '1.2.4');
      const env = { home, shell: config.shell, install };

      const first = runInstaller({ ...env, fixture: fixtureA, tag: 'v1.2.3' });
      assert.equal(first.status, 0, first.stderr);
      assert.match(first.stdout, /added .* to PATH/);
      const wired = readFileSync(rc, 'utf8');
      assert.ok(wired.includes(`\n${marker}\n`), 'the first install added the marker');
      assert.ok(wired.includes(config.pathLine(install)), 'the first install added the PATH line');

      // Re-running the installer upgrades the binaries but must not append a
      // second PATH block: the marker short-circuit leaves the file unchanged.
      const second = runInstaller({ ...env, fixture: fixtureB, tag: 'v1.2.4' });
      assert.equal(second.status, 0, second.stderr);
      assert.match(second.stdout, /installed to /);
      assert.match(second.stdout, /already wired into/);
      assert.doesNotMatch(second.stdout, /added .* to PATH/,
        'the second install must not append another PATH block');
      assert.equal(readFileSync(rc, 'utf8'), wired,
        'the second install left the startup file byte-for-byte unchanged');

      const lines = assertSingleManagedBlock(rc, config, install);
      if (scenario === 'pre-existing') {
        assert.ok(lines.includes('export EDITOR=vim'),
          'pre-existing startup content is preserved across both installs');
      }

      // The repeat was a real install, not a skipped one: the staged binaries
      // and receipt moved to the new fixture version and every staging,
      // backup, and lock sibling is gone.
      const version = spawnSync(join(install, 'phantom'), ['--version'], { encoding: 'utf8' });
      assert.equal(version.status, 0);
      assert.equal(version.stdout.trim(), 'phantom 1.2.4',
        'the second install actually upgraded the binaries');
      assert.equal(
        JSON.parse(readFileSync(join(install, '.phantom-install-source.json'), 'utf8')).version,
        '1.2.4');
      assert.deepEqual(readdirSync(dirname(install)), ['bin'],
        'no staging, backup, or lock is left beside the install directory');
    });
  }
}

// A repeat from a shell that already sourced the wired rc (the resolved PATH
// contains the install dir) must skip add_to_user_path entirely: the exact
// PATH-entry gate fires before the function runs, so no PATH message prints
// and the startup file is again untouched.
for (const [shellName, config] of Object.entries(shells)) {
  test(`public installer skips the ${shellName} rc update when the install dir is already on PATH`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-public-path-sourced-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const home = join(root, 'home');
    const install = join(root, 'live', 'bin');
    const rc = config.rc(home);
    mkdirSync(home, { recursive: true });
    const fixtureA = buildFixture(root, '1.2.3');
    const fixtureB = buildFixture(root, '1.2.4');
    const env = { home, shell: config.shell, install };

    const first = runInstaller({ ...env, fixture: fixtureA, tag: 'v1.2.3' });
    assert.equal(first.status, 0, first.stderr);
    assert.match(first.stdout, /added .* to PATH/);
    const wired = readFileSync(rc, 'utf8');

    const second = runInstaller({ ...env, fixture: fixtureB, tag: 'v1.2.4', pathPrefix: install });
    assert.equal(second.status, 0, second.stderr);
    assert.match(second.stdout, /installed to /);
    assert.doesNotMatch(second.stdout, /already wired into|added .* to PATH/,
      'an install dir already on PATH never reaches the rc update');
    assert.equal(readFileSync(rc, 'utf8'), wired,
      'the repeat install left the startup file byte-for-byte unchanged');

    assertSingleManagedBlock(rc, config, install);
    assert.deepEqual(readdirSync(dirname(install)), ['bin'],
      'no staging, backup, or lock is left beside the install directory');
  });
}

// Re-installing into a different install dir (for example a changed
// PHANTOM_INSTALL_DIR) must still leave a single installer-managed entry:
// the marker owns the block, so the second run wires nothing new.
for (const [shellName, config] of Object.entries(shells)) {
  test(`public installer keeps one ${shellName} PATH entry when the repeat uses a different install dir`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-public-path-rebin-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const home = join(root, 'home');
    const installA = join(root, 'a', 'bin');
    const installB = join(root, 'b', 'bin');
    const rc = config.rc(home);
    mkdirSync(home, { recursive: true });
    const fixtureA = buildFixture(root, '1.2.3');
    const fixtureB = buildFixture(root, '1.2.4');

    const first = runInstaller({ home, shell: config.shell, install: installA, fixture: fixtureA, tag: 'v1.2.3' });
    assert.equal(first.status, 0, first.stderr);
    assert.match(first.stdout, /added .* to PATH/);
    const wired = readFileSync(rc, 'utf8');

    const second = runInstaller({ home, shell: config.shell, install: installB, fixture: fixtureB, tag: 'v1.2.4' });
    assert.equal(second.status, 0, second.stderr);
    assert.match(second.stdout, /already wired into/);
    assert.doesNotMatch(second.stdout, /added .* to PATH/);
    assert.equal(readFileSync(rc, 'utf8'), wired,
      'the repeat install left the startup file byte-for-byte unchanged');

    const lines = assertSingleManagedBlock(rc, config, installA);
    assert.equal(
      lines.filter((line) => line === config.pathLine(installB)).length, 0,
      'the changed install dir did not stack a second PATH line');
  });
}
