import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import test from 'node:test';

// Every add_to_user_path call must take its snapshot (.phantom-path.before.*)
// at a fresh mktemp path, never a fixed or reused name. The harness runs the
// shipped function twice in one shell (the second call finds the marker
// already wired) and a mktemp shim records every path created, so the test
// compares the two real snapshot paths.
const copies = {
  'scripts/install.sh': resolve(import.meta.dirname, 'install.sh'),
  'apps/web/public/install.sh': resolve(import.meta.dirname, '..', 'apps', 'web', 'public', 'install.sh'),
};

// Same extraction as installer-path-snapshot-cleanup.test.mjs.
function extractFunction(source, name, file) {
  const start = source.indexOf(`${name}()`);
  assert.ok(start >= 0, `${file}: locate ${name}`);
  const lineEnd = source.indexOf('\n', start);
  if (source.slice(start, lineEnd).trimEnd().endsWith('}')) return source.slice(start, lineEnd + 1);
  const end = source.indexOf('\n}\n', start);
  assert.ok(end > start, `${file}: locate end of ${name}`);
  return source.slice(start, end + '\n}\n'.length);
}

for (const [file, installer] of Object.entries(copies)) {
  const source = readFileSync(installer, 'utf8');
  const harness = ['set -euo pipefail', 'umask 077',
    ...['say', 'file_identity', 'file_link_count', 'add_to_user_path']
      .map((name) => extractFunction(source, name, file)),
    'add_to_user_path "$1"', 'add_to_user_path "$1"',
  ].join('\n');

  test(`${file} creates a distinct PATH snapshot path on each call`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-snapshot-distinct-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const home = join(root, 'home');
    const bin = join(root, 'bin');
    const shims = join(root, 'shims');
    const created = join(root, 'mktemp-created');
    for (const dir of [home, bin, shims]) mkdirSync(dir);
    const mktemp = execFileSync('which', ['mktemp'], { encoding: 'utf8' }).trim();
    writeFileSync(join(shims, 'mktemp'), `#!/bin/sh
out="$(${JSON.stringify(mktemp)} "$@")" || exit
printf '%s\\n' "$out" >> "$PHANTOM_TEST_MKTEMP_CREATED"
printf '%s\\n' "$out"
`);
    chmodSync(join(shims, 'mktemp'), 0o755);

    const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
      encoding: 'utf8',
      timeout: 30000,
      cwd: root,
      env: {
        HOME: home,
        SHELL: '/bin/bash',
        PATH: `${shims}:/usr/bin:/bin`,
        PHANTOM_TEST_MKTEMP_CREATED: created,
      },
    });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /added .* to PATH/);
    assert.match(result.stdout, /already wired into/);

    const paths = readFileSync(created, 'utf8').trim().split('\n');
    const snapshots = paths.filter((p) => basename(p).startsWith('.phantom-path.before.'));
    assert.equal(snapshots.length, 2, 'one snapshot per call');
    assert.notEqual(snapshots[0], snapshots[1], 'the two snapshots have distinct paths');
    for (const p of snapshots) assert.equal(dirname(p), home);
    assert.equal(new Set(paths).size, paths.length, 'no temporary path is reused');
  });
}
