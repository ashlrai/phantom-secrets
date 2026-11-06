import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync,
  readFileSync, realpathSync, rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import test from 'node:test';

// When post-move validation fails (the moved candidate does not pass the
// final checks), add_to_user_path must restore the original startup file
// from the before-snapshot and remove all .phantom-path temporary files.
// This test injects the failure through a grep shim that rejects the
// post-move marker check, then asserts the recovery contract end-to-end.
const copies = {
  'scripts/install.sh': resolve(import.meta.dirname, 'install.sh'),
  'apps/web/public/install.sh': resolve(import.meta.dirname, '..', 'apps', 'web', 'public', 'install.sh'),
};

const original = '# user shell config\nexport EDITOR=vim\n';

// Same extraction as installer-path-update-failure-cleanup.test.mjs: anchors
// the search to a line boundary so short names like "warn" don't match
// inside add_to_user_path, and detects single-line functions.
function extractFunction(source, name, file) {
  const anchored = source.indexOf('\n' + name + '()');
  const start = anchored >= 0 ? anchored + 1 : source.indexOf(name + '()');
  assert.ok(start >= 0, file + ': locate ' + name);
  const lineEnd = source.indexOf('\n', start);
  assert.ok(lineEnd > start, file + ': locate end of ' + name);
  if (source.slice(start, lineEnd).trimEnd().endsWith('}')) {
    return source.slice(start, lineEnd + 1);
  }
  const end = source.indexOf('\n}\n', start);
  assert.ok(end > start, file + ': locate end of ' + name);
  return source.slice(start, end + '\n}\n'.length);
}

function harness(source, file) {
  return ['set -euo pipefail', 'umask 077',
    ...['say', 'warn', 'file_identity', 'file_link_count', 'add_to_user_path']
      .map((n) => extractFunction(source, n, file)),
    'if add_to_user_path "$1"; then',
    '  exit 0',
    'else',
    '  status=$?',
    '  warn "could not update your shell PATH; add $1 manually"',
    '  exit "$status"',
    'fi',
  ].join('\n');
}

const realMktemp = spawnSync('/usr/bin/which', ['mktemp'], { encoding: 'utf8' }).stdout.trim();
const realGrep = spawnSync('/usr/bin/which', ['grep'], { encoding: 'utf8' }).stdout.trim();

function makeShims(root) {
  const shims = join(root, 'shims');
  mkdirSync(shims);
  writeFileSync(join(shims, 'mktemp'), `#!/bin/sh
created="$("${realMktemp}" "$@")" || exit $?
printf '%s\\n' "$created" >> "$PHANTOM_CREATED"
printf '%s\\n' "$created"
`);
  writeFileSync(join(shims, 'grep'), `#!/bin/sh
for arg do last="$arg"; done
case "$last" in *.phantom-path.*) exec ${realGrep} "$@" ;; *) exit 1 ;; esac
`);
  for (const name of readdirSync(shims)) chmodSync(join(shims, name), 0o755);
  return shims;
}

function runPostMoveFailure(t, source, file, shell) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-post-move-recovery-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const home = join(root, 'home');
  const shims = makeShims(root);
  const rc = shell.rc(home);
  mkdirSync(dirname(rc), { recursive: true });
  writeFileSync(rc, original, { mode: 0o600 });
  const createdFile = join(root, 'created');

  const script = harness(source, file);
  const result = spawnSync('/bin/bash', ['-c', script, 'path-test', join(root, 'bin')], {
    encoding: 'utf8',
    timeout: 30000,
    env: { HOME: home, SHELL: shell.bin, PATH: `${shims}:/usr/bin:/bin`, PHANTOM_CREATED: createdFile },
  });
  assert.ifError(result.error);

  const createdPaths = readFileSync(createdFile, 'utf8').trim().split('\n')
    .filter((p) => p.includes('.phantom-path.'));

  return { rc, root, home, result, createdPaths, rcBase: basename(rc) };
}

const shells = [
  { name: 'bash', bin: '/bin/bash', rc: (h) => join(h, '.bashrc') },
  { name: 'zsh', bin: '/bin/zsh', rc: (h) => join(h, '.zshrc') },
  { name: 'fish', bin: '/usr/bin/fish', rc: (h) => join(h, '.config', 'fish', 'config.fish') },
];

for (const [file, installer] of Object.entries(copies)) {
  const source = readFileSync(installer, 'utf8');
  for (const shell of shells) {
    test(`${file} restores the startup file and cleans temporaries on post-move failure (${shell.name})`, (t) => {
      const { rc, root, home, result, createdPaths, rcBase } = runPostMoveFailure(t, source, file, shell);

      assert.equal(result.status, 1, 'the update must report failure');
      assert.match(result.stderr, /could not update your shell PATH/, 'failure is warned');

      // Both temp files existed mid-update; none survive.
      assert.equal(createdPaths.length, 2, 'both temporary files were created');
      for (const path of createdPaths) {
        assert.equal(existsSync(path), false,
          'temporary file must be removed: ' + path);
      }

      // No .phantom-path file survives anywhere under the test root.
      assert.deepEqual(
        readdirSync(root, { recursive: true })
          .filter((entry) => typeof entry === 'string' && entry.startsWith('.phantom-path.')),
        [],
        'no .phantom-path temporary file survives anywhere',
      );

      // The original shell configuration is restored byte-for-byte.
      assert.equal(readFileSync(rc, 'utf8'), original,
        'the original startup file is restored');

      // The startup-file parent contains only the startup file.
      const rcDir = dirname(rc);
      assert.deepEqual(readdirSync(rcDir), [rcBase],
        'the startup-file parent contains only the startup file');
    });
  }
}
