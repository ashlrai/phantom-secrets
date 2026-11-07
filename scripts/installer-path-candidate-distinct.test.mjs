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
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { pathUpdateHarness } from './lib/installer-path-harness.mjs';

// Each PATH update builds its startup-file replacement through two mktemp
// siblings — a `.phantom-path.before.XXXXXX` snapshot and the
// `.phantom-path.candidate.XXXXXX` file promoted onto the startup file. The
// XXXXXX templates are what keep a repeat update from colliding with the
// previous run's files: a fixed name would be reused every time and could
// race a concurrent installer on the same parent. This drives the shipped
// add_to_user_path twice in a row behind an mktemp that records the real
// path each call creates, so the names are observed on disk rather than
// inferred from the template strings. The second update still creates both
// files before the marker check short-circuits it, so two updates record
// exactly two candidates — which must have distinct paths.
const copies = {
  'scripts/install.sh': resolve(import.meta.dirname, 'install.sh'),
  'apps/web/public/install.sh': resolve(import.meta.dirname, '..', 'apps', 'web', 'public', 'install.sh'),
};

// add_to_user_path runs under `set -euo pipefail` in the installer and calls
// these helpers; extract the exact same text so the exercised code is the
// shipped code. Single-line helpers like say() end on their opening line.
const harnesses = Object.fromEntries(
  Object.entries(copies).map(([file, path]) => [file, pathUpdateHarness(readFileSync(path, 'utf8'), file)]),
);

const realMktemp = execFileSync('/usr/bin/which', ['mktemp'], { encoding: 'utf8', env: { PATH: '/usr/bin:/bin' } }).trim();

// Delegates to the real mktemp and records every .phantom-path.* path it
// creates, so each logged path is a file the installer really made there.
function makeMktempShim(root, log) {
  const shims = join(root, 'shims');
  mkdirSync(shims);
  writeFileSync(join(shims, 'mktemp'), `#!/bin/sh
out="$(${JSON.stringify(realMktemp)} "$@")" || exit
case "$1" in
  *.phantom-path.*)
    [ -f "$out" ] || exit 3
    printf '%s\\n' "$out" >> ${JSON.stringify(log)}
    ;;
esac
printf '%s\\n' "$out"
`);
  chmodSync(join(shims, 'mktemp'), 0o755);
  return shims;
}

function runPathUpdate(body, { home, bin, shims }) {
  const result = spawnSync('/bin/bash', ['-c', body, 'path-test', bin], {
    encoding: 'utf8',
    timeout: 30000,
    env: { HOME: home, SHELL: '/bin/bash', PATH: `${shims}:/usr/bin:/bin` },
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  return result;
}

// The acceptance predicate: two updates create exactly two candidates, and
// the two candidate paths differ.
function distinctCandidates(log) {
  const created = readFileSync(log, 'utf8').trim().split('\n');
  const candidates = created.filter((path) => basename(path).startsWith('.phantom-path.candidate.'));
  assert.equal(candidates.length, 2, 'two updates must create exactly two PATH candidates');
  assert.notEqual(candidates[0], candidates[1],
    'two PATH candidates must have distinct paths');
  return candidates;
}

for (const [file, body] of Object.entries(harnesses)) {
  test(`${file} gives two PATH candidates distinct paths across repeated updates`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-candidates-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const home = join(root, 'home');
    const bin = join(root, 'live', 'bin');
    const log = join(root, 'created.log');
    mkdirSync(home);
    mkdirSync(bin, { recursive: true });
    const rc = join(home, '.bashrc');
    writeFileSync(rc, '# user shell configuration\n', { mode: 0o600 });
    const shims = makeMktempShim(root, log);

    const first = runPathUpdate(body, { home, bin, shims });
    assert.match(first.stdout, /added .* to PATH/);
    const second = runPathUpdate(body, { home, bin, shims });
    assert.match(second.stdout, /already wired into/,
      'the repeat update must still run (marker short-circuits after creating both files)');

    distinctCandidates(log);
    const created = readFileSync(log, 'utf8').trim().split('\n');
    const befores = created.filter((path) => basename(path).startsWith('.phantom-path.before.'));
    assert.equal(created.length, 4, 'two updates create two snapshots and two candidates');
    assert.equal(befores.length, 2, 'two updates create two snapshots');
    for (const path of created) {
      assert.match(basename(path), /^\.phantom-path\.(before|candidate)\.[^/]+$/,
        `${path} must keep its mktemp name`);
      assert.equal(realpathSync(dirname(path)), realpathSync(home),
        `${path} must sit beside the startup file`);
    }
    assert.notEqual(befores[0], befores[1], 'two snapshots must have distinct paths');
    assert.equal(new Set(created).size, created.length,
      'no temporary path may repeat across updates');
    assert.deepEqual(
      readdirSync(home).filter((name) => name.startsWith('.phantom-path.')),
      [],
      'no PATH temporary file may survive the repeated updates',
    );
  });
}

// A candidate name that stops being fresh would reuse one path every run;
// the check must catch that instead of passing vacuously.
test('the distinct-path check rejects a reused candidate name', (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-candidate-fixed-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const home = join(root, 'home');
  const bin = join(root, 'live', 'bin');
  const log = join(root, 'created.log');
  const shims = join(root, 'shims');
  mkdirSync(home);
  mkdirSync(bin, { recursive: true });
  mkdirSync(shims);
  writeFileSync(join(home, '.bashrc'), '# user shell configuration\n', { mode: 0o600 });
  writeFileSync(join(shims, 'mktemp'), `#!/bin/sh
case "$1" in
  *.phantom-path.candidate.*)
    out="$(dirname "$1")/.phantom-path.candidate.FIXED"
    : > "$out" || exit 1
    ;;
  *)
    out="$(${JSON.stringify(realMktemp)} "$@")" || exit
    ;;
esac
printf '%s\\n' "$out" >> ${JSON.stringify(log)}
printf '%s\\n' "$out"
`);
  chmodSync(join(shims, 'mktemp'), 0o755);

  const body = harnesses['scripts/install.sh'];
  const env = { home, bin, shims };
  assert.match(runPathUpdate(body, env).stdout, /added .* to PATH/);
  assert.match(runPathUpdate(body, env).stdout, /already wired into/);
  assert.throws(() => distinctCandidates(log), /distinct paths/);
});
