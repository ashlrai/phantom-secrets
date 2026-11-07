import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import test from 'node:test';

// When HOME is a symlink to a directory whose name contains spaces, the PATH
// update resolves the shell configuration directory with `pwd -P` and must
// create BOTH temporary files (.phantom-path.before.* and
// .phantom-path.candidate.*) directly inside that resolved spaced directory —
// not under the symlink, not under TMPDIR — and leave neither behind.
const copies = {
  'scripts/install.sh': resolve(import.meta.dirname, 'install.sh'),
  'apps/web/public/install.sh': resolve(import.meta.dirname, '..', 'apps', 'web', 'public', 'install.sh'),
};

function extract(source, name, file) {
  const start = source.indexOf(`${name}()`);
  assert.ok(start >= 0, `${file}: locate ${name}`);
  const lineEnd = source.indexOf('\n', start);
  if (source.slice(start, lineEnd).trimEnd().endsWith('}')) return source.slice(start, lineEnd + 1);
  const end = source.indexOf('\n}\n', start);
  assert.ok(end > start, `${file}: locate end of ${name}`);
  return source.slice(start, end + '\n}\n'.length);
}

const realMktemp = execFileSync('which', ['mktemp'], { encoding: 'utf8' }).trim();

for (const [file, installer] of Object.entries(copies)) {
  const source = readFileSync(installer, 'utf8');
  const body = ['set -euo pipefail', 'umask 077',
    ...['say', 'file_identity', 'file_link_count', 'add_to_user_path'].map((n) => extract(source, n, file)),
    'add_to_user_path "$1"'].join('\n');

  test(`${file} creates both PATH temporary files in a spaced directory reached through a HOME symlink`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-spaced-symlink-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const realHome = join(root, 'real home with spaces');
    const linkHome = join(root, 'link');
    const shims = join(root, 'shims');
    const elsewhere = join(root, 'tmp elsewhere');
    for (const dir of [realHome, shims, elsewhere]) mkdirSync(dir);
    symlinkSync(realHome, linkHome);
    const rc = join(realHome, '.bashrc');
    writeFileSync(rc, '# user config\n', { mode: 0o600 });
    const created = join(root, 'created.log');
    writeFileSync(join(shims, 'mktemp'), `#!/bin/sh
out="$(${JSON.stringify(realMktemp)} "$@")" || exit
printf '%s\\n' "$out" >> ${JSON.stringify(created)}
printf '%s\\n' "$out"
`);
    chmodSync(join(shims, 'mktemp'), 0o755);

    const result = spawnSync('/bin/bash', ['-c', body, 'spaced-symlink', join(root, 'bin')], {
      encoding: 'utf8',
      timeout: 30000,
      env: { HOME: linkHome, SHELL: '/bin/bash', PATH: `${shims}:/usr/bin:/bin`, TMPDIR: elsewhere },
    });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /added .* to PATH/);

    const paths = readFileSync(created, 'utf8').trim().split('\n');
    assert.equal(paths.length, 2, 'exactly two temporary files are created');
    assert.match(basename(paths[0]), /^\.phantom-path\.before\./);
    assert.match(basename(paths[1]), /^\.phantom-path\.candidate\./);
    for (const path of paths) {
      assert.equal(dirname(path), realHome, `${path} must be inside the resolved spaced directory`);
    }
    assert.deepEqual(readdirSync(realHome), ['.bashrc'], 'both temporary files are gone afterwards');
    assert.deepEqual(readdirSync(elsewhere), [], 'nothing is created under TMPDIR');
  });
}
