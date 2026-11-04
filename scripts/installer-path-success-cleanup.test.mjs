import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import test from 'node:test';

// A successful PATH update must leave nothing behind in the startup-file
// directory: the .phantom-path.before.XXXXXX snapshot is removed and the
// .phantom-path.candidate.XXXXXX replacement was moved over the startup
// file — no .phantom-path.* sibling may remain. Two legs assert it:
//
// 1. A portable leg drives the shipped add_to_user_path — extracted
//    byte-for-byte from each installer — to success under a scratch HOME,
//    on every shell/rc-state combination, on any platform.
// 2. An end-to-end leg runs the real installer against a local release
//    fixture. It is registered only on Linux: macOS stamps
//    archive-extracted executables with com.apple.provenance and denies
//    their interpreter under Gatekeeper assessment, so fixture binaries
//    cannot run there; CI runs the installer end-to-end on Linux.
const copies = {
  'scripts/install.sh': resolve(import.meta.dirname, 'install.sh'),
  'apps/web/public/install.sh': resolve(import.meta.dirname, '..', 'apps', 'web', 'public', 'install.sh'),
};

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

const pathTemps = (entry) => basename(entry).startsWith('.phantom-path.');

// add_to_user_path runs under `set -euo pipefail` in the installer and calls
// these helpers; extract the exact same text so the exercised code is the
// shipped code. Single-line helpers like say() end on their opening line.
// Same extraction as installer-path-snapshot-cleanup.test.mjs.
function extractFunction(source, name, file) {
  const start = source.indexOf(`${name}()`);
  assert.ok(start >= 0, `${file}: locate ${name}`);
  const lineEnd = source.indexOf('\n', start);
  assert.ok(lineEnd > start, `${file}: locate end of ${name}`);
  if (source.slice(start, lineEnd).trimEnd().endsWith('}')) {
    return source.slice(start, lineEnd + 1);
  }
  const end = source.indexOf('\n}\n', start);
  assert.ok(end > start, `${file}: locate end of ${name}`);
  return source.slice(start, end + '\n}\n'.length);
}

function pathUpdateHarness(source, file) {
  return ['set -euo pipefail', 'umask 077',
    ...['say', 'file_identity', 'file_link_count', 'add_to_user_path']
      .map((name) => extractFunction(source, name, file)),
    'add_to_user_path "$1"',
  ].join('\n');
}

// The mktemp shim delegates to the real tool and records every
// .phantom-path.* path it creates, proving the siblings existed mid-update
// so their absence afterwards means they were removed.
function makeMktempShim(root, log) {
  const shims = join(root, 'shims');
  mkdirSync(shims, { recursive: true });
  const mktemp = execFileSync('which', ['mktemp'], { encoding: 'utf8' }).trim();
  writeFileSync(join(shims, 'mktemp'), `#!/bin/sh
created="$(${JSON.stringify(mktemp)} "$@")" || exit $?
case "$created" in */.phantom-path.*) printf '%s\\n' "$created" >> ${JSON.stringify(log)} ;; esac
printf '%s\\n' "$created"
`);
  chmodSync(join(shims, 'mktemp'), 0o755);
  return shims;
}

// Reads the paths the mktemp shim recorded: exactly the snapshot then the
// candidate, both inside the startup file's parent.
function createdSiblings(log, rcParent) {
  const created = readFileSync(log, 'utf8').trim().split('\n');
  assert.equal(created.length, 2, 'both PATH-update temporary files were created');
  assert.match(basename(created[0]), /^\.phantom-path\.before\.[^/]+$/);
  assert.match(basename(created[1]), /^\.phantom-path\.candidate\.[^/]+$/);
  for (const createdPath of created) {
    assert.equal(dirname(createdPath), rcParent,
      'the temporary siblings are created inside the startup-file parent');
  }
  return created;
}

// The cleanup contract this file exists to pin: after success, the exact
// snapshot and candidate paths mktemp created are gone, the startup-file
// directory holds no .phantom-path.* entry, and none survives anywhere
// under the test root.
function assertSiblingsRemoved(created, { root, rc }) {
  for (const createdPath of created) {
    assert.equal(existsSync(createdPath), false,
      `temporary sibling must be removed after success: ${basename(createdPath)}`);
  }
  assert.deepEqual(readdirSync(dirname(rc)).filter(pathTemps), [],
    'no PATH-update temporary file may remain beside the startup file');
  assert.deepEqual(readdirSync(root, { recursive: true }).filter(pathTemps), [],
    'no PATH-update temporary file may survive anywhere after a successful update');
}

// Runs the extracted add_to_user_path under a scratch HOME exactly as the
// installer drives it. With rcContent the startup file is written at mode
// 600 first; without it the file (and, for fish, its nested parent) is left
// absent so the installer's own mkdir -p creates it.
function runPathUpdate(t, harness, config, rcContent) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-success-cleanup-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const home = join(root, 'home with spaces');
  const bin = join(root, 'bin');
  const scratch = join(root, 'scratch');
  const rc = config.rc(home);
  if (rcContent === undefined) {
    mkdirSync(home, { recursive: true });
  } else {
    mkdirSync(dirname(rc), { recursive: true });
    writeFileSync(rc, rcContent, { mode: 0o600 });
  }
  mkdirSync(bin);
  mkdirSync(scratch);
  const log = join(root, 'mktemp-created');
  const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
    encoding: 'utf8',
    timeout: 30000,
    cwd: scratch,
    env: {
      HOME: home,
      SHELL: config.shell,
      PATH: `${makeMktempShim(root, log)}:/usr/bin:/bin`,
    },
  });
  assert.ifError(result.error);
  return { bin, log, rc, result, root, scratch };
}

for (const [file, installer] of Object.entries(copies)) {
  const harness = pathUpdateHarness(readFileSync(installer, 'utf8'), file);
  for (const [shellName, config] of Object.entries(shells)) {
    test(`${file} removes the PATH-update temporary files after a successful ${shellName} update`, (t) => {
      const original = '# user shell config\nexport EDITOR=vim\n';
      const { bin, log, rc, result, root } = runPathUpdate(t, harness, config, original);
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, /added .* to PATH/);
      const created = createdSiblings(log, dirname(rc));
      assertSiblingsRemoved(created, { root, rc });
      assert.equal(readFileSync(rc, 'utf8'),
        `${original}\n# phantom-secrets PATH\n${config.pathLine(bin)}\n`);
      assert.equal(lstatSync(rc).mode & 0o777, 0o600,
        'the updated startup file keeps its private mode');
    });

    test(`${file} removes the PATH-update temporary files after a successful ${shellName} update with an absent startup file`, (t) => {
      const { bin, log, rc, result, root } = runPathUpdate(t, harness, config, undefined);
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, /added .* to PATH/);
      const created = createdSiblings(log, dirname(rc));
      assertSiblingsRemoved(created, { root, rc });
      assert.equal(readFileSync(rc, 'utf8'),
        `\n# phantom-secrets PATH\n${config.pathLine(bin)}\n`);
      assert.equal(lstatSync(rc).mode & 0o777, 0o600,
        'the created startup file is private');
    });

    test(`${file} removes the PATH-update temporary files after a ${shellName} update that finds the marker already wired`, (t) => {
      const wired = '# user shell config\n\n# phantom-secrets PATH\n'
        + `${config.pathLine('/opt/phantom-secrets/bin')}\n`;
      const { log, rc, result, root } = runPathUpdate(t, harness, config, wired);
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, /already wired into/);
      const created = createdSiblings(log, dirname(rc));
      assertSiblingsRemoved(created, { root, rc });
      assert.equal(readFileSync(rc, 'utf8'), wired,
        'an already-wired startup file is left byte-for-byte unchanged');
    });
  }
}

// End-to-end: the real installer installs from a local offline release
// fixture and the PATH update runs inside the full install, ending in
// `say "done. ..."`. Registered only where archive-extracted fixture
// executables can run: Linux.
function makeReleaseFixture(root, archive, version) {
  const fixture = join(root, 'fixture');
  const payload = join(root, 'payload');
  mkdirSync(fixture);
  mkdirSync(payload);
  for (const name of ['phantom', 'phantom-mcp']) {
    writeFileSync(join(payload, name), `#!/bin/sh\nprintf '${name} ${version}\\n'\n`, { mode: 0o755 });
  }
  execFileSync('tar', ['-czf', join(fixture, archive), '-C', payload, 'phantom', 'phantom-mcp']);
  const digest = createHash('sha256').update(readFileSync(join(fixture, archive))).digest('hex');
  writeFileSync(join(fixture, `${archive}.sha256`), `${digest}  ${archive}\n`);
  return fixture;
}

if (process.platform === 'linux') {
  const version = '1.2.3';
  const os = { darwin: 'apple-darwin', linux: 'unknown-linux-gnu' }[process.platform];
  const arch = { x64: 'x86_64', arm64: 'aarch64' }[process.arch];
  const archive = `phantom-${arch}-${os}.tar.gz`;

  for (const [file, installer] of Object.entries(copies)) {
    for (const [shellName, config] of Object.entries(shells)) {
      for (const existing of [false, true]) {
        test(`${file} installer cleans PATH files after ${shellName} install (existing rc: ${existing})`, (t) => {
          const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-install-path-')));
          t.after(() => rmSync(root, { recursive: true, force: true }));
          const fixture = makeReleaseFixture(root, archive, version);
          const home = join(root, 'home with spaces');
          const install = join(root, 'live', 'bin');
          const rc = config.rc(home);
          const original = '# existing configuration\n';
          if (existing) {
            mkdirSync(dirname(rc), { recursive: true });
            writeFileSync(rc, original);
          } else {
            mkdirSync(home, { recursive: true });
          }
          const log = join(root, 'mktemp-created');
          const result = spawnSync('/bin/bash', [installer], {
            encoding: 'utf8',
            timeout: 30000,
            env: {
              HOME: home,
              SHELL: config.shell,
              PATH: `${makeMktempShim(root, log)}:/usr/bin:/bin`,
              PHANTOM_INSTALL_DIR: install,
              PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
              PHANTOM_TEST_LOCAL_RELEASE_DIR: fixture,
              PHANTOM_TAG: `v${version}`,
            },
          });
          assert.ifError(result.error);
          assert.equal(result.status, 0, result.stderr);
          assert.match(result.stdout, /added .* to PATH/);
          assert.equal(readFileSync(rc, 'utf8'),
            `${existing ? original : ''}\n# phantom-secrets PATH\n${config.pathLine(install)}\n`);
          const created = createdSiblings(log, dirname(rc));
          assertSiblingsRemoved(created, { root, rc });
        });
      }
    }
  }
}
