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

// The PATH update snapshots the shell startup file into a private sibling
// (.phantom-path.before.XXXXXX) and builds its replacement next to it
// (.phantom-path.candidate.XXXXXX). When the startup file's parent directory
// contains spaces, each mktemp template must still reach mktemp as exactly one
// argument and the snapshot must be created inside that same spaced parent —
// never split into the filesystem around it.
const copies = {
  'scripts/install.sh': resolve(import.meta.dirname, 'install.sh'),
  'apps/web/public/install.sh': resolve(import.meta.dirname, '..', 'apps', 'web', 'public', 'install.sh'),
};

// add_to_user_path runs under `set -euo pipefail` in the installer and calls
// these helpers; extract the exact same text so the exercised code is the
// shipped code. Single-line helpers like say() end on their opening line.
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

// The shims record a line-per-argument argv log — a word-split template shows
// up as extra lines — then delegate to the real tool. The mktemp shim also
// records each path it actually creates so the test can prove the snapshot
// landed inside the spaced parent rather than merely name-checking the call.
function makeShims(root) {
  const shims = join(root, 'shims');
  mkdirSync(shims);
  const mktemp = execFileSync('which', ['mktemp'], { encoding: 'utf8' }).trim();
  const cp = execFileSync('which', ['cp'], { encoding: 'utf8' }).trim();
  writeFileSync(join(shims, 'mktemp'), `#!/bin/sh
{
  printf -- '--call--\\n'
  printf '%s\\n' "$@"
} >> "$PHANTOM_TEST_MKTEMP_CALLS"
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

for (const [file, installer] of Object.entries(copies)) {
  const harness = pathUpdateHarness(readFileSync(installer, 'utf8'), file);
  for (const [shellName, config] of Object.entries(shells)) {
    test(`${file} creates the PATH snapshot inside a space-containing ${shellName} rc parent`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-snapshot-spaces-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home dir with spaces');
      const bin = join(root, 'bin');
      const scratch = join(root, 'scratch');
      const rc = config.rc(home);
      mkdirSync(dirname(rc), { recursive: true });
      mkdirSync(bin);
      mkdirSync(scratch);
      const original = '# user shell config\nexport EDITOR=vim\n';
      writeFileSync(rc, original, { mode: 0o600 });
      const rcParent = dirname(rc);

      const shims = makeShims(root);
      const mktempCalls = join(root, 'mktemp-calls');
      const mktempCreated = join(root, 'mktemp-created');
      const cpCalls = join(root, 'cp-calls');
      const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
        encoding: 'utf8',
        timeout: 30000,
        cwd: scratch,
        env: {
          HOME: home,
          SHELL: config.shell,
          PATH: `${shims}:/usr/bin:/bin`,
          PHANTOM_TEST_MKTEMP_CALLS: mktempCalls,
          PHANTOM_TEST_MKTEMP_CREATED: mktempCreated,
          PHANTOM_TEST_CP_CALLS: cpCalls,
        },
      });
      assert.ifError(result.error);
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, /added .* to PATH/);

      // Each PATH-update template must arrive as exactly one mktemp argument;
      // a word-split spaced parent would appear as extra argv lines here.
      const pathCalls = callsLog(mktempCalls)
        .filter((call) => call.some((arg) => arg.includes('.phantom-path.')));
      assert.deepEqual(pathCalls, [
        [join(rcParent, '.phantom-path.before.XXXXXX')],
        [join(rcParent, '.phantom-path.candidate.XXXXXX')],
      ], 'before and candidate templates are each a single argument in the spaced parent');

      // mktemp really created both sibling files inside the spaced parent, not
      // in a truncated or split-off location.
      const created = readFileSync(mktempCreated, 'utf8').trim().split('\n')
        .filter((path) => path.includes('.phantom-path.'));
      assert.equal(created.length, 2, 'both PATH-update temporary files were created');
      const [beforePath, candidatePath] = created;
      for (const createdPath of created) {
        assert.equal(dirname(createdPath), rcParent,
          'the snapshot must be created directly inside the spaced rc parent');
      }
      assert.match(basename(beforePath), /^\.phantom-path\.before\.[^/]+$/);
      assert.match(basename(candidatePath), /^\.phantom-path\.candidate\.[^/]+$/);

      // The snapshot is a private copy of the startup file at that spaced
      // path, and the candidate is built from the snapshot beside it.
      const snapshotCopies = callsLog(cpCalls).filter((call) => call[0] === '-p');
      assert.deepEqual(snapshotCopies, [
        ['-p', rc, beforePath],
        ['-p', beforePath, candidatePath],
      ], 'cp -p must snapshot the startup file inside the spaced parent');

      // Nothing escaped into the working directory and no temporary siblings
      // remain; the startup file gained only the marker and the PATH line.
      assert.deepEqual(readdirSync(scratch), [],
        'no path fragment may be created beside the working directory');
      assert.deepEqual(readdirSync(rcParent), [basename(rc)],
        'the spaced parent must be left with only the updated startup file');
      assert.equal(readFileSync(rc, 'utf8'),
        `${original}\n# phantom-secrets PATH\n${config.pathLine(bin)}\n`);
    });
  }
}
