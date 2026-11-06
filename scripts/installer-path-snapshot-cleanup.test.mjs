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
import { basename, dirname, join, resolve } from 'node:path';
import test from 'node:test';

// The PATH update builds its replacement through two private siblings in
// the startup file's parent: the snapshot (.phantom-path.before.XXXXXX), a
// cp -p copy of the startup file — or an empty file when it is absent —
// and the candidate (.phantom-path.candidate.XXXXXX) that mv moves over
// the startup file. A snapshot duplicates whatever private configuration
// the startup file already held, so a successful update must not leave it
// behind. These tests drive the shipped add_to_user_path to success on
// every branch that creates the siblings — an existing startup file, an
// absent one, and the already-wired marker check — then prove the exact
// paths mktemp created no longer exist and no .phantom-path.* entry
// survives anywhere under the test root. Asserting on the recorded paths
// is stronger than listing the startup-file parent: it names the file
// that was deleted, not just a directory that looks clean.
const copies = {
  'scripts/install.sh': resolve(import.meta.dirname, 'install.sh'),
  'apps/web/public/install.sh': resolve(import.meta.dirname, '..', 'apps', 'web', 'public', 'install.sh'),
};

// add_to_user_path runs under `set -euo pipefail` in the installer and calls
// these helpers; extract the exact same text so the exercised code is the
// shipped code. Single-line helpers like say() end on their opening line.
// Same extraction as installer-path-snapshot-spaces.test.mjs.
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

function callsLog(file) {
  return existsSync(file)
    ? readFileSync(file, 'utf8').split('--call--\n').slice(1)
      .map((entry) => entry.split('\n').filter(Boolean))
    : [];
}

// The mktemp shim delegates to the real tool and records each path it
// actually creates, so a cleanup assertion names a file that provably
// existed mid-update rather than merely an empty-looking directory. The
// cp shim records a line-per-argument argv log proving the deleted
// snapshot held a real cp -p copy of the startup file.
function makeShims(root) {
  const shims = join(root, 'shims');
  mkdirSync(shims);
  const mktemp = execFileSync('which', ['mktemp'], { encoding: 'utf8' }).trim();
  const cp = execFileSync('which', ['cp'], { encoding: 'utf8' }).trim();
  writeFileSync(join(shims, 'mktemp'), `#!/bin/sh
created="$(${JSON.stringify(mktemp)} "$@")" || exit
printf '%s\\n' "$created" >> "$PHANTOM_TEST_MKTEMP_CREATED"
printf '%s\\n' "$created"
`);
  writeFileSync(join(shims, 'cp'), `#!/bin/sh
{
  printf -- '--call--\\n'
  printf '%s\\n' "$@"
} >> "$PHANTOM_TEST_CP_CALLS"
exec ${JSON.stringify(cp)} "$@"
`);
  for (const name of readdirSync(shims)) chmodSync(join(shims, name), 0o755);
  return shims;
}

// Runs the extracted add_to_user_path under a scratch HOME exactly as the
// installer drives it. With rcContent the startup file is written at mode
// 600 first; without it the file (and, for fish, its nested parent) is
// left absent so the installer's own mkdir -p creates it.
function runPathUpdate(t, harness, config, rcContent) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-snapshot-cleanup-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const home = join(root, 'home');
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
  const logs = {
    mktempCreated: join(root, 'mktemp-created'),
    cpCalls: join(root, 'cp-calls'),
  };
  const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
    encoding: 'utf8',
    timeout: 30000,
    cwd: scratch,
    env: {
      HOME: home,
      SHELL: config.shell,
      PATH: `${makeShims(root)}:/usr/bin:/bin`,
      PHANTOM_TEST_MKTEMP_CREATED: logs.mktempCreated,
      PHANTOM_TEST_CP_CALLS: logs.cpCalls,
    },
  });
  assert.ifError(result.error);
  return { bin, logs, rc, result, root, scratch };
}

// Reads the paths the mktemp shim recorded: exactly the snapshot then the
// candidate, both inside the startup file's parent. Returning them lets
// the test assert on the precise files a successful update must remove.
function createdSiblings({ mktempCreated }, rcParent) {
  const created = readFileSync(mktempCreated, 'utf8').trim().split('\n')
    .filter((path) => path.includes('.phantom-path.'));
  assert.equal(created.length, 2, 'both PATH-update temporary files were created');
  for (const createdPath of created) {
    assert.equal(dirname(createdPath), rcParent,
      'the temporary siblings are created inside the startup-file parent');
  }
  assert.match(basename(created[0]), /^\.phantom-path\.before\.[^/]+$/);
  assert.match(basename(created[1]), /^\.phantom-path\.candidate\.[^/]+$/);
  return created;
}

function snapshotCopies(logs) {
  return callsLog(logs.cpCalls).filter((call) => call[0] === '-p');
}

// The cleanup contract this file exists to pin: after success, the exact
// snapshot and candidate paths mktemp created are gone — the candidate
// moved over the startup file and the snapshot removed — and no
// .phantom-path.* entry survives anywhere under the test root, including
// beside the working directory.
function assertSiblingsRemoved(created, { root, rc, scratch }) {
  for (const createdPath of created) {
    assert.equal(existsSync(createdPath), false,
      `temporary sibling must be removed after success: ${basename(createdPath)}`);
  }
  assert.deepEqual(
    readdirSync(root, { recursive: true })
      .filter((entry) => basename(entry).startsWith('.phantom-path.')),
    [],
    'no PATH-update temporary file may survive anywhere after a successful update');
  assert.deepEqual(readdirSync(dirname(rc)), [basename(rc)],
    'the startup-file parent must be left with only the startup file');
  assert.deepEqual(readdirSync(scratch), [],
    'no path fragment may be created beside the working directory');
}

for (const [file, installer] of Object.entries(copies)) {
  const harness = pathUpdateHarness(readFileSync(installer, 'utf8'), file);
  for (const [shellName, config] of Object.entries(shells)) {
    test(`${file} removes the PATH snapshot after a successful ${shellName} update`, (t) => {
      const original = '# user shell config\nexport EDITOR=vim\n';
      const { bin, logs, rc, result, root, scratch } =
        runPathUpdate(t, harness, config, original);
      const rcParent = dirname(rc);
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, /added .* to PATH/);

      // The snapshot really existed mid-update: mktemp created it beside
      // the startup file and cp -p filled it with the startup content,
      // then the candidate copied it.
      const created = createdSiblings(logs, rcParent);
      assert.deepEqual(snapshotCopies(logs), [
        ['-p', rc, created[0]],
        ['-p', created[0], created[1]],
      ], 'the removed snapshot held a private copy of the startup file');

      assertSiblingsRemoved(created, { root, rc, scratch });
      assert.equal(readFileSync(rc, 'utf8'),
        `${original}\n# phantom-secrets PATH\n${config.pathLine(bin)}\n`);
    });

    test(`${file} removes the empty PATH snapshot after a successful ${shellName} update with an absent startup file`, (t) => {
      const { bin, logs, rc, result, root, scratch } =
        runPathUpdate(t, harness, config, undefined);
      const rcParent = dirname(rc);
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, /added .* to PATH/);

      // Both siblings still exist mid-update; without a startup file to
      // copy the snapshot stays empty and no cp -p runs.
      const created = createdSiblings(logs, rcParent);
      assert.deepEqual(snapshotCopies(logs), [],
        'without a startup file there is nothing to snapshot with cp -p');

      assertSiblingsRemoved(created, { root, rc, scratch });
      assert.equal(readFileSync(rc, 'utf8'),
        `\n# phantom-secrets PATH\n${config.pathLine(bin)}\n`);
    });

    test(`${file} removes the PATH snapshot after a ${shellName} update that finds the marker already wired`, (t) => {
      const wired = '# user shell config\n\n# phantom-secrets PATH\n'
        + `${config.pathLine('/opt/phantom-secrets/bin')}\n`;
      const { logs, rc, result, root, scratch } =
        runPathUpdate(t, harness, config, wired);
      const rcParent = dirname(rc);
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, /already wired into/);

      // The marker check reads the snapshot, so both siblings are still
      // created — and still must be removed — before the short-circuit.
      const created = createdSiblings(logs, rcParent);
      assert.deepEqual(snapshotCopies(logs), [['-p', rc, created[0]]],
        'the snapshot is taken for the marker check before the short-circuit');

      assertSiblingsRemoved(created, { root, rc, scratch });
      assert.equal(readFileSync(rc, 'utf8'), wired,
        'an already-wired startup file is left byte-for-byte unchanged');
    });
  }
}
