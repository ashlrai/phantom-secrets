import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, utimesSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

// The second PATH update must not even touch the startup file: same bytes,
// same inode, same mtime. Byte equality alone would pass a rewrite that
// replaces the file with identical content (breaking symlink-free hard-link
// and file-watcher expectations), so this pins the stronger "no write" form.
// Switching SHELL wires that shell's own startup file but must leave the
// first shell's file untouched.
const copies = {
  'scripts/install.sh': resolve(import.meta.dirname, 'install.sh'),
  'apps/web/public/install.sh': resolve(import.meta.dirname, '..', 'apps', 'web', 'public', 'install.sh'),
};

function extractFunction(source, name, file) {
  const start = source.indexOf(`${name}()`);
  assert.ok(start >= 0, `${file}: locate ${name}`);
  const lineEnd = source.indexOf('\n', start);
  if (source.slice(start, lineEnd).trimEnd().endsWith('}')) return source.slice(start, lineEnd + 1);
  const end = source.indexOf('\n}\n', start);
  assert.ok(end > start, `${file}: locate end of ${name}`);
  return source.slice(start, end + '\n}\n'.length);
}

const harnessFor = (source, file) => ['set -euo pipefail', 'umask 077',
  ...['say', 'file_identity', 'file_link_count', 'add_to_user_path']
    .map((name) => extractFunction(source, name, file)),
  'add_to_user_path "$1"',
].join('\n');

const run = (harness, shell, home, bin) => {
  const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
    encoding: 'utf8',
    timeout: 30000,
    env: { HOME: home, SHELL: shell, PATH: '/usr/bin:/bin' },
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  return result;
};

for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  test(`${file} second PATH update does not rewrite the startup file`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-untouched-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const home = join(root, 'home');
    const bin = join(root, 'bin');
    mkdirSync(home, { recursive: true });
    mkdirSync(bin, { recursive: true });
    const rc = join(home, '.zshrc');

    assert.match(run(harness, '/bin/zsh', home, bin).stdout, /added .* to PATH/);
    // Age the file so an accidental rewrite would visibly move the mtime.
    const old = new Date('2020-01-01T00:00:00Z');
    utimesSync(rc, old, old);
    const bytes = readFileSync(rc);
    const before = statSync(rc);

    const assertUntouched = () => {
      const after = statSync(rc);
      assert.deepEqual(readFileSync(rc), bytes, 'bytes unchanged');
      assert.equal(after.ino, before.ino, 'same inode: file not replaced');
      assert.equal(after.mtimeMs, before.mtimeMs, 'mtime unchanged: file not written');
    };
    assert.match(run(harness, '/bin/zsh', home, bin).stdout, /already wired into/);
    assertUntouched();
    assert.match(run(harness, '/bin/bash', home, bin).stdout, /added .* to PATH/);
    assertUntouched();
  });
}
