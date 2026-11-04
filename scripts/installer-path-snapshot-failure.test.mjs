import assert from 'node:assert/strict';
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

// The PATH update builds the snapshot (.phantom-path.before.XXXXXX) and the
// candidate (.phantom-path.candidate.XXXXXX) with `cp -p`: the snapshot copies
// the existing startup file, then the candidate copies the snapshot before the
// marker and PATH line are appended. A failed `cp -p` must be reported through
// the installer's warning call site, must remove both siblings, and must leave
// the startup file byte-for-byte and inode-for-inode unchanged — a half-taken
// snapshot can never become a partial rewrite. The mktemp failure of either
// sibling is covered by installer-path-temp-failure.test.mjs and
// installers.test.js; this file covers the copy failures after both siblings
// exist, including the case where the snapshot fails ahead of the
// already-wired short-circuit that would otherwise print a success line.
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

// The trailing line mirrors the installer's call site, where a failed update
// is reported as a warning and is not fatal to the installation: under `||`,
// `set -e` is suspended inside the function, so every explicit guard in the
// function is load-bearing exactly as in production.
function pathUpdateHarness(source, file) {
  return ['set -euo pipefail', 'umask 077',
    ...['say', 'warn', 'file_identity', 'file_link_count', 'add_to_user_path']
      .map((name) => extractFunction(source, name, file)),
    'add_to_user_path "$1" || warn "could not update your shell PATH; add $1 manually"',
  ].join('\n');
}

function callsLog(file) {
  return existsSync(file)
    ? readFileSync(file, 'utf8').split('--call--\n').slice(1)
      .map((entry) => entry.split('\n').filter(Boolean))
    : [];
}

// The cp shim records a line-per-argument argv log — so the test can prove the
// failing seam was actually reached — then fails any copy whose destination is
// the sibling selected by PHANTOM_TEST_FAIL_COPY ('before' or 'candidate') and
// delegates every other call to the real tool.
function makeShims(root) {
  const shims = join(root, 'shims');
  mkdirSync(shims);
  const cp = execFileSync('which', ['cp'], { encoding: 'utf8' }).trim();
  writeFileSync(join(shims, 'cp'), `#!/bin/sh
{
  printf -- '--call--\\n'
  printf '%s\\n' "$@"
} >> "$PHANTOM_TEST_CP_CALLS"
last=""
for arg in "$@"; do last="$arg"; done
case "$last" in
  *.phantom-path."$PHANTOM_TEST_FAIL_COPY".*) exit 1 ;;
esac
exec ${JSON.stringify(cp)} "$@"
`);
  chmodSync(join(shims, 'cp'), 0o755);
  return shims;
}

// Runs the extracted add_to_user_path under a scratch HOME with an existing
// bash startup file at mode 600, exactly as the installer drives it. The
// scratch root is resolved physically because the function resolves the rc
// parent with pwd -P; the cp argv it logs then matches the test's own paths.
function runPathUpdate(t, harness, failCopy, rcContent) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-snapshot-failure-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const home = join(root, 'home');
  const bin = join(root, 'bin');
  const scratch = join(root, 'scratch');
  const rc = join(home, '.bashrc');
  mkdirSync(home);
  mkdirSync(bin);
  mkdirSync(scratch);
  writeFileSync(rc, rcContent, { mode: 0o600 });
  const before = lstatSync(rc);
  const logs = { cpCalls: join(root, 'cp-calls') };
  const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
    encoding: 'utf8',
    timeout: 30000,
    cwd: scratch,
    env: {
      HOME: home,
      SHELL: '/bin/bash',
      PATH: `${makeShims(root)}:/usr/bin:/bin`,
      PHANTOM_TEST_CP_CALLS: logs.cpCalls,
      PHANTOM_TEST_FAIL_COPY: failCopy,
    },
  });
  assert.ifError(result.error);
  return { bin, logs, rc, result, before, scratch };
}

// The reported contract: the warning call site fires, no success line is
// printed, and the startup file is untouched in content, inode, and mode.
// No temporary sibling or path fragment may survive anywhere.
function assertReportedWithoutTouchingRc({ result, rc, original, before, scratch }) {
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, '', 'a failed update prints no success lines');
  assert.match(result.stderr, /could not update your shell PATH/);
  assert.equal(readFileSync(rc, 'utf8'), original,
    'the startup file must be byte-for-byte unchanged');
  const after = lstatSync(rc);
  assert.equal(after.ino, before.ino, 'the startup file must not be replaced');
  assert.equal(after.mode, before.mode);
  assert.deepEqual(readdirSync(dirname(rc)), [basename(rc)],
    'both temporary siblings must be removed');
  assert.deepEqual(readdirSync(scratch), [],
    'no path fragment may be created beside the working directory');
}

function snapshotCopyCalls(logs) {
  return callsLog(logs.cpCalls).filter((call) => call[0] === '-p');
}

for (const [file, installer] of Object.entries(copies)) {
  const source = readFileSync(installer, 'utf8');
  const harness = pathUpdateHarness(source, file);

  test(`${file} reports a PATH snapshot copy failure without changing the startup file`, (t) => {
    const original = '# user shell config\nexport EDITOR=vim\n';
    const { logs, rc, result, before, scratch } =
      runPathUpdate(t, harness, 'before', original);
    const rcParent = dirname(rc);

    // The snapshot copy was attempted and aborted at its only cp -p call;
    // the candidate copy is never reached.
    const calls = snapshotCopyCalls(logs);
    assert.equal(calls.length, 1, 'only the snapshot copy may run');
    assert.equal(calls[0][1], rc);
    assert.equal(dirname(calls[0][2]), rcParent);
    assert.match(basename(calls[0][2]), /^\.phantom-path\.before\./);

    assertReportedWithoutTouchingRc({ result, rc, original, before, scratch });
  });

  test(`${file} reports a PATH candidate copy failure without changing the startup file`, (t) => {
    const original = '# user shell config\nexport EDITOR=vim\n';
    const { logs, rc, result, before, scratch } =
      runPathUpdate(t, harness, 'candidate', original);
    const rcParent = dirname(rc);

    // The snapshot copy succeeded, then building the candidate from the
    // snapshot failed; the appended PATH line is never written and the move
    // is never reached.
    const calls = snapshotCopyCalls(logs);
    assert.equal(calls.length, 2, 'snapshot copy then candidate copy');
    assert.equal(calls[0][1], rc);
    assert.match(basename(calls[0][2]), /^\.phantom-path\.before\./);
    assert.equal(calls[1][1], calls[0][2], 'the candidate copies the snapshot');
    assert.equal(dirname(calls[1][2]), rcParent);
    assert.match(basename(calls[1][2]), /^\.phantom-path\.candidate\./);

    assertReportedWithoutTouchingRc({ result, rc, original, before, scratch });
  });

  test(`${file} reports a PATH snapshot copy failure ahead of the already-wired short-circuit`, (t) => {
    const original = '# user shell config\n\n# phantom-secrets PATH\n'
      + 'export PATH="/old/bin:$PATH"\n';
    const { logs, rc, result, before, scratch } =
      runPathUpdate(t, harness, 'before', original);

    // A failed snapshot must be reported even where a successful one would
    // have short-circuited with "already wired".
    assert.equal(snapshotCopyCalls(logs).length, 1);
    assertReportedWithoutTouchingRc({ result, rc, original, before, scratch });
  });
}

// Both `cp -p` calls carry the same guard contract: on failure remove both
// temporary siblings and return nonzero. The runtime tests above prove the
// behavior; this pins the guard text in both installer copies.
function copyGuard(body, source, destination, file) {
  const call = `cp -p "$${source}" "$${destination}"`;
  const index = body.indexOf(call);
  assert.ok(index >= 0, `${file}: missing ${call}`);
  assert.equal(body.indexOf(call, index + call.length), -1,
    `${file}: duplicate ${call}`);
  const tail = body.slice(index + call.length);
  assert.match(
    tail,
    /^ \|\| \{\n {6}rm -f -- "\$before_tmp" "\$candidate_tmp"\n {6}return 1\n {4}\}\n/,
    `${file}: a failed ${destination} copy must remove both siblings and abort`,
  );
  return index;
}

for (const [file, installer] of Object.entries(copies)) {
  test(`${file} guards each PATH snapshot copy with sibling cleanup`, () => {
    const body = extractFunction(readFileSync(installer, 'utf8'), 'add_to_user_path', file);
    assert.equal(body.match(/cp -p "/g)?.length ?? 0, 2,
      `${file}: the PATH update makes exactly two cp -p copies`);
    const beforeIndex = copyGuard(body, 'rc', 'before_tmp', file);
    const candidateIndex = copyGuard(body, 'before_tmp', 'candidate_tmp', file);
    assert.ok(beforeIndex < candidateIndex,
      `${file}: the startup file is snapshotted before the candidate is built`);
  });
}

test('both installer copies carry the identical PATH-update function', () => {
  assert.equal(
    extractFunction(readFileSync(copies['scripts/install.sh'], 'utf8'), 'add_to_user_path', 'scripts/install.sh'),
    extractFunction(readFileSync(copies['apps/web/public/install.sh'], 'utf8'), 'add_to_user_path', 'apps/web/public/install.sh'),
    'PATH-update copy guards must match across installer copies',
  );
});

test('the copy-guard check rejects an unguarded snapshot copy', () => {
  const body = extractFunction(
    readFileSync(copies['scripts/install.sh'], 'utf8'), 'add_to_user_path', 'fixture');
  const unguarded = body.replace(
    'cp -p "$rc" "$before_tmp" || {\n      rm -f -- "$before_tmp" "$candidate_tmp"\n      return 1\n    }',
    'cp -p "$rc" "$before_tmp"',
  );
  assert.notEqual(unguarded, body, 'the fixture must contain the guard to strip');
  assert.throws(() => copyGuard(unguarded, 'rc', 'before_tmp', 'fixture'),
    /must remove both siblings/);
});
