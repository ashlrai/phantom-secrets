import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
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

// The PATH update builds its replacement through two private siblings of the
// startup file — the .phantom-path.before.XXXXXX snapshot and the
// .phantom-path.candidate.XXXXXX replacement — and every failure exit after
// their creation must remove both before the update reports failure. A
// leftover sibling is more than litter: it is a mode-600 copy of the user's
// private shell configuration parked beside the real file. Sibling tests
// cover failure inside mktemp itself (installer-path-temp-failure.test.mjs,
// installer-path-snapshot-failure.test.mjs) and cleanup after success
// (installer-path-snapshot-cleanup.test.mjs). This file drives the failure
// exits that run while both siblings exist — inspection, copies, candidate
// move, post-move validation, mid-update modification of the startup file,
// and unsafe pre-existing startup-file states — plus the warning the full
// installer prints when add_to_user_path fails, asserting each failure is
// reported and no .phantom-path.* entry survives anywhere.
const copies = {
  'scripts/install.sh': resolve(import.meta.dirname, 'install.sh'),
  'apps/web/public/install.sh': resolve(import.meta.dirname, '..', 'apps', 'web', 'public', 'install.sh'),
};

const original = '# user shell config\nexport EDITOR=vim\n';
const racedReplacement = '# replaced by another process\n';
const racedAppend = '\n# concurrent edit\n';
const racedArrival = '# appeared during the update\n';

// Same extraction as installer-path-snapshot-cleanup.test.mjs: the exercised
// code is the shipped code. The call site is reproduced too — the installer
// invokes add_to_user_path in a `|| warn` context, which suppresses errexit
// inside the whole function, so every guarded command must carry its own
// `|| return 1`. The harness preserves that context and the warning.
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
    ...['say', 'warn', 'file_identity', 'file_link_count', 'add_to_user_path']
      .map((name) => extractFunction(source, name, file)),
    'if add_to_user_path "$1"; then',
    '  exit 0',
    'else',
    '  status=$?',
    '  warn "could not update your shell PATH; add $1 manually"',
    '  exit "$status"',
    'fi',
  ].join('\n');
}

const shells = {
  bash: { shell: '/bin/bash', rc: (home) => join(home, '.bashrc') },
  fish: { shell: '/usr/bin/fish', rc: (home) => join(home, '.config', 'fish', 'config.fish') },
};

// Every seam shim delegates non-matching calls to the real tool it shadows,
// so the update runs the shipped code path up to the injected failure.
const real = {};
for (const tool of ['mktemp', 'cp', 'mv', 'chmod', 'stat', 'grep', 'mkdir']) {
  real[tool] = execFileSync('which', [tool], { encoding: 'utf8' }).trim();
}
const q = JSON.stringify;

// The mktemp shim records every path it creates, proving the siblings
// existed mid-update so their absence afterwards means they were removed.
// cp drives three seams: a refused snapshot or candidate copy, and a
// concurrent writer that replaces, edits, or deletes the startup file
// between the snapshot and the pre-move re-verification. mv refuses the
// candidate move; chmod refuses to secure the siblings or simulates a
// startup file appearing mid-update; stat refuses inspection; grep fails
// only the post-move marker check; mkdir refuses the fish parent.
function makeShims(root) {
  const shims = join(root, 'shims');
  mkdirSync(shims);
  const scripts = {
    mktemp: `#!/bin/sh
created="$(${q(real.mktemp)} "$@")" || exit
printf '%s\\n' "$created" >> "$PHANTOM_TEST_MKTEMP_CREATED"
printf '%s\\n' "$created"
`,
    cp: `#!/bin/sh
for arg do last="$arg"; done
case "$last" in
  *.phantom-path.before.*)
    [ "$PHANTOM_TEST_SEAM" = 'snapshot-copy' ] && exit 1
    ${q(real.cp)} "$@" || exit
    if [ "$PHANTOM_TEST_SEAM" = 'rc-replaced' ]; then
      printf '%s\\n' '${racedReplacement.trimEnd()}' > "$PHANTOM_TEST_RACE_RC.race"
      ${q(real.mv)} -f "$PHANTOM_TEST_RACE_RC.race" "$PHANTOM_TEST_RACE_RC"
    fi
    exit 0
    ;;
  *.phantom-path.candidate.*)
    [ "$PHANTOM_TEST_SEAM" = 'candidate-copy' ] && exit 1
    ${q(real.cp)} "$@" || exit
    case "$PHANTOM_TEST_SEAM" in
      rc-modified) printf '%s\\n' '' '# concurrent edit' >> "$PHANTOM_TEST_RACE_RC" ;;
      rc-removed) rm -f -- "$PHANTOM_TEST_RACE_RC" ;;
    esac
    exit 0
    ;;
esac
exec ${q(real.cp)} "$@"
`,
    mv: `#!/bin/sh
src="$1"
[ "$src" = '-f' ] && src="$2"
case "$src" in
  *.phantom-path.candidate.*) [ "$PHANTOM_TEST_SEAM" = 'move' ] && exit 1 ;;
esac
exec ${q(real.mv)} "$@"
`,
    chmod: `#!/bin/sh
phantom=0
for arg do
  case "$arg" in *.phantom-path.*) phantom=1 ;; esac
done
if [ "$phantom" -eq 1 ]; then
  case "$PHANTOM_TEST_SEAM" in
    secure-temps) exit 1 ;;
    rc-appeared)
      ${q(real.chmod)} "$@" || exit
      printf '%s\\n' '${racedArrival.trimEnd()}' > "$PHANTOM_TEST_RACE_RC"
      exit 0
      ;;
  esac
fi
exec ${q(real.chmod)} "$@"
`,
    stat: `#!/bin/sh
for arg do last="$arg"; done
case "$last" in
  *.phantom-path.candidate.*) [ "$PHANTOM_TEST_SEAM" = 'candidate-identity' ] && exit 1 ;;
  *.phantom-path.*) ;;
  *)
    if [ "$PHANTOM_TEST_SEAM" = 'inspect' ]; then exit 1; fi
    if [ "$PHANTOM_TEST_SEAM" = 'identity' ]; then
      for arg do
        case "$arg" in *:*) exit 1 ;; esac
      done
    fi
    ;;
esac
exec ${q(real.stat)} "$@"
`,
    grep: `#!/bin/sh
for arg do last="$arg"; done
if [ "$PHANTOM_TEST_SEAM" = 'post-move' ]; then
  case "$last" in *.phantom-path.*) ;; *) exit 1 ;; esac
fi
exec ${q(real.grep)} "$@"
`,
    mkdir: `#!/bin/sh
if [ "$PHANTOM_TEST_SEAM" = 'parent-mkdir' ]; then
  for arg do
    case "$arg" in *fish*) exit 1 ;; esac
  done
fi
exec ${q(real.mkdir)} "$@"
`,
  };
  for (const [name, script] of Object.entries(scripts)) {
    writeFileSync(join(shims, name), script, { mode: 0o755 });
  }
  return shims;
}

// Runs the extracted add_to_user_path under a scratch HOME exactly as the
// installer drives it. rcState 'file' writes the startup file at mode 600;
// 'symlink', 'directory', and 'hardlink' install the unsafe pre-existing
// states the update must refuse; 'absent' leaves it missing so the update's
// own mkdir -p creates any nested parent (fish).
function runPathUpdate(t, harness, config, { seam = '', rcState = 'file' } = {}) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-update-failure-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const home = join(root, 'home');
  const bin = join(root, 'bin');
  const scratch = join(root, 'scratch');
  const rc = config.rc(home);
  mkdirSync(bin);
  mkdirSync(scratch);
  let beforeStat;
  if (rcState === 'absent') {
    mkdirSync(home, { recursive: true });
  } else {
    mkdirSync(dirname(rc), { recursive: true });
    if (rcState === 'symlink') {
      const target = join(root, 'rc-target');
      writeFileSync(target, original, { mode: 0o600 });
      symlinkSync(target, rc);
    } else if (rcState === 'directory') {
      mkdirSync(rc);
    } else {
      writeFileSync(rc, original, { mode: 0o600 });
      if (rcState === 'hardlink') linkSync(rc, join(root, 'rc-linked'));
      beforeStat = lstatSync(rc);
    }
  }
  const created = join(root, 'mktemp-created');
  const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
    encoding: 'utf8',
    timeout: 30000,
    cwd: scratch,
    env: {
      HOME: home,
      SHELL: config.shell,
      PATH: `${makeShims(root)}:/usr/bin:/bin`,
      PHANTOM_TEST_SEAM: seam,
      PHANTOM_TEST_RACE_RC: rc,
      PHANTOM_TEST_MKTEMP_CREATED: created,
    },
  });
  assert.ifError(result.error);
  const temps = existsSync(created)
    ? readFileSync(created, 'utf8').trim().split('\n')
      .filter((path) => path.includes('.phantom-path.'))
    : [];
  return { bin, beforeStat, home, rc, result, root, scratch, temps };
}

// The failure contract: nonzero exit, the failure reported through the
// installer's warning, and no success claim.
function assertFailureReported({ result }) {
  assert.equal(result.status, 1, `the failed update must exit 1\nstdout: ${result.stdout}\nstderr: ${result.stderr}`);
  assert.match(result.stderr, /could not update your shell PATH/,
    'the failure must be reported through the installer warning');
  assert.doesNotMatch(result.stdout, /added .* to PATH/);
}

// The cleanup contract: the exact siblings mktemp created are gone, no
// .phantom-path.* entry survives anywhere under the test root, and nothing
// was written beside the working directory.
function assertNoTempFiles({ root, scratch, temps }, expectedTemps = 2) {
  assert.equal(temps.length, expectedTemps,
    'the PATH-update temporary files must have been created before the failure');
  for (const path of temps) {
    assert.equal(existsSync(path), false,
      `temporary sibling must be removed after failure: ${basename(path)}`);
  }
  assert.deepEqual(
    readdirSync(root, { recursive: true })
      .filter((entry) => basename(entry).startsWith('.phantom-path.')),
    [],
    'no PATH-update temporary file may survive anywhere after a failed update');
  assert.deepEqual(readdirSync(scratch), [],
    'no path fragment may be created beside the working directory');
}

function assertUntouchedRc({ beforeStat, rc }) {
  assert.equal(readFileSync(rc, 'utf8'), original, 'startup file bytes unchanged');
  const after = lstatSync(rc);
  assert.equal(after.ino, beforeStat.ino, 'startup file not replaced');
  assert.equal(after.mode & 0o777, 0o600, 'startup file mode unchanged');
}

const updatedRc = (bin) =>
  `${original}\n# phantom-secrets PATH\nexport PATH="${bin}:$PATH"\n`;
const createdRc = (bin) =>
  `\n# phantom-secrets PATH\nexport PATH="${bin}:$PATH"\n`;

// Failure exits reachable while the startup file exists but is not changed
// by another writer: inspection refusals, copy failures, the candidate
// move, and the post-move validation. The startup file must remain
// byte-for-byte identical except where the seam itself defines otherwise.
const existingRcSeams = [
  { seam: 'inspect', label: 'the startup file cannot be inspected', expect: 'untouched' },
  { seam: 'identity', label: 'the startup file identity cannot be verified', expect: 'untouched' },
  { seam: 'snapshot-copy', label: 'the snapshot copy fails', expect: 'untouched' },
  { seam: 'candidate-copy', label: 'the candidate copy fails', expect: 'untouched' },
  { seam: 'candidate-identity', label: 'the candidate cannot be inspected', expect: 'untouched' },
  { seam: 'move', label: 'the candidate cannot be moved over the startup file', expect: 'untouched' },
  // A concurrent writer replaces, edits, or deletes the startup file between
  // the snapshot and the pre-move re-verification. The update must refuse
  // and leave the other writer's state — never restore, merge, or delete it.
  { seam: 'rc-replaced', label: 'the startup file is replaced mid-update', expect: racedReplacement },
  { seam: 'rc-modified', label: 'the startup file is edited mid-update', expect: (bin) => `${original}${racedAppend}` },
  { seam: 'rc-removed', label: 'the startup file is deleted mid-update', expect: 'absent' },
  // The startup file is restored from its snapshot when the post-move validation
  // cannot confirm the update: before_tmp serves as the rollback target,
  // and no .phantom-path temporary file survives.
  { seam: 'post-move', label: 'the post-move validation cannot confirm the update', expect: 'restored' },
];

// Failure exits reachable when the startup file is absent: securing the
// empty siblings, a startup file appearing mid-update, the candidate move,
// and the post-move validation.
const absentRcSeams = [
  { seam: 'secure-temps', label: 'the temporary siblings cannot be secured', expect: 'absent' },
  { seam: 'rc-appeared', label: 'a startup file appears mid-update', expect: racedArrival },
  { seam: 'candidate-identity', label: 'the candidate cannot be inspected', expect: 'absent' },
  { seam: 'move', label: 'the candidate cannot be moved over the startup file', expect: 'absent' },
  { seam: 'post-move', label: 'the post-move validation cannot confirm the update', expect: 'absent' },
];

function assertRcExpectation({ bin, beforeStat, rc }, expect) {
  if (expect === 'untouched') return assertUntouchedRc({ beforeStat, rc });
  if (expect === 'absent') {
    assert.equal(existsSync(rc), false, 'the update must not recreate the startup file');
    return;
  }
  if (expect === 'restored') {
    assert.equal(readFileSync(rc, 'utf8'), original, 'startup file content restored')
    const restored = lstatSync(rc)
    assert.equal(restored.mode & 0o777, 0o600, 'startup file mode restored')
    return
  }
  const content = typeof expect === 'function' ? expect(bin) : expect;
  assert.equal(readFileSync(rc, 'utf8'), content, 'startup file left in its raced state');
}

for (const [file, installer] of Object.entries(copies)) {
  const harness = pathUpdateHarness(readFileSync(installer, 'utf8'), file);

  for (const { seam, label, expect } of existingRcSeams) {
    test(`${file} removes the PATH-update temporary files when ${label}`, (t) => {
      const run = runPathUpdate(t, harness, shells.bash, { seam });
      assertFailureReported(run);
      assertNoTempFiles(run);
      assertRcExpectation(run, expect);
    });
  }

  for (const rcState of ['symlink', 'directory', 'hardlink']) {
    test(`${file} removes the PATH-update temporary files when the startup file is a ${rcState}`, (t) => {
      const run = runPathUpdate(t, harness, shells.bash, { rcState });
      assertFailureReported(run);
      assertNoTempFiles(run);
      if (rcState === 'symlink') {
        assert.ok(lstatSync(run.rc).isSymbolicLink(), 'the symlink itself is left in place');
        assert.equal(readFileSync(join(run.root, 'rc-target'), 'utf8'), original,
          'the symlink target is never written');
      } else if (rcState === 'directory') {
        assert.ok(lstatSync(run.rc).isDirectory(), 'the directory is left in place');
      } else {
        assert.equal(lstatSync(run.rc).nlink, 2, 'the extra link is left in place');
        assert.equal(readFileSync(run.rc, 'utf8'), original);
        assert.equal(readFileSync(join(run.root, 'rc-linked'), 'utf8'), original);
      }
    });
  }

  for (const { seam, label, expect } of absentRcSeams) {
    test(`${file} removes the PATH-update temporary files when ${label} with an absent startup file`, (t) => {
      const run = runPathUpdate(t, harness, shells.bash, { seam, rcState: 'absent' });
      assertFailureReported(run);
      assertNoTempFiles(run);
      assertRcExpectation(run, expect);
      if (expect === 'absent') {
        assert.deepEqual(readdirSync(run.home), [],
          'an absent startup file stays absent, including its parent entries');
      }
    });
  }

  // The fish branch differs only in its rc location, nested parent, and
  // PATH line; spot-check representative seams on both sides of the branch.
  test(`${file} removes the fish PATH-update temporary files when the candidate move fails`, (t) => {
    const run = runPathUpdate(t, harness, shells.fish, { seam: 'move' });
    assertFailureReported(run);
    assertNoTempFiles(run);
    assertRcExpectation(run, 'untouched');
  });

  test(`${file} removes the fish PATH-update temporary files when a startup file appears mid-update`, (t) => {
    const run = runPathUpdate(t, harness, shells.fish, { seam: 'rc-appeared', rcState: 'absent' });
    assertFailureReported(run);
    assertNoTempFiles(run);
    assertRcExpectation(run, racedArrival);
  });

  // The parent-directory creation fails before any temporary file exists;
  // failure is still reported and nothing is left behind.
  test(`${file} reports failure and creates nothing when the fish startup-file parent cannot be created`, (t) => {
    const run = runPathUpdate(t, harness, shells.fish, { seam: 'parent-mkdir', rcState: 'absent' });
    assertFailureReported(run);
    assertNoTempFiles(run, 0);
    assert.deepEqual(readdirSync(run.home), []);
  });
}

// The reporting contract on the shipped file: the PATH update is invoked
// only when the install directory is missing from PATH, and its failure is
// reported through the installer warning instead of aborting the install.
for (const [file, installer] of Object.entries(copies)) {
  test(`${file} reports a failed PATH update through its warning call site`, () => {
    const source = readFileSync(installer, 'utf8');
    const gate = 'if ! printf \'%s\\n\' "$PATH" | tr \':\' \'\\n\' | grep -qxF "$INSTALL_DIR"; then';
    const call = 'add_to_user_path "$INSTALL_DIR" || warn "could not update your shell PATH; add $INSTALL_DIR manually"';
    const gateIndex = source.indexOf(gate);
    const callIndex = source.indexOf(call);
    assert.ok(gateIndex >= 0, `${file}: the exact PATH membership check must gate the update`);
    assert.ok(callIndex > gateIndex,
      `${file}: a failed PATH update must be reported through the warning call site`);
  });
}

// End-to-end: the real installer script installs from a local offline
// release fixture while a seam fails the PATH update. The installer must
// warn about the failed update, still finish the install, and leave no
// .phantom-path.* siblings beside the startup file.
function makeReleaseFixture(root) {
  const fixture = join(root, 'fixture');
  const payload = join(root, 'payload');
  mkdirSync(fixture);
  mkdirSync(payload);
  for (const name of ['phantom', 'phantom-mcp']) {
    writeFileSync(join(payload, name), `#!/bin/sh\necho "${name} 1.2.3"\n`);
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

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function runInstaller(t, installer, { seam, rcState }) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-installer-path-failure-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const fixture = makeReleaseFixture(root);
  const home = join(root, 'home');
  const install = join(root, 'live', 'bin');
  const rc = join(home, '.bashrc');
  mkdirSync(home, { recursive: true });
  if (rcState === 'file') writeFileSync(rc, original, { mode: 0o600 });
  const env = { ...process.env };
  for (const name of [
    'PHANTOM_REPO', 'PHANTOM_TAG', 'PHANTOM_INSTALL_DIR',
    'PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES', 'PHANTOM_TEST_LOCAL_RELEASE_DIR',
    'PHANTOM_TEST_FAIL_AFTER_PROMOTION', 'PHANTOM_INSTALL_LOCK_WAIT_SECONDS',
    'PHANTOM_INSTALL_LOCK_STALE_SECONDS', 'PHANTOM_INSTALL_LOCK_HEARTBEAT_SECONDS',
    'PHANTOM_TEST_SEAM', 'PHANTOM_TEST_RACE_RC', 'PHANTOM_TEST_MKTEMP_CREATED',
  ]) delete env[name];
  const result = spawnSync('/bin/bash', [installer], {
    encoding: 'utf8',
    timeout: 30000,
    env: {
      ...env,
      HOME: home,
      SHELL: '/bin/bash',
      // The install directory is deliberately not on PATH so the installer
      // runs add_to_user_path; the seam shims then inject the failure.
      PATH: `${makeShims(root)}:/usr/local/bin:/usr/bin:/bin`,
      PHANTOM_INSTALL_DIR: install,
      PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
      PHANTOM_TEST_LOCAL_RELEASE_DIR: fixture,
      PHANTOM_TAG: 'v1.2.3',
      PHANTOM_TEST_SEAM: seam,
      PHANTOM_TEST_RACE_RC: rc,
      PHANTOM_TEST_MKTEMP_CREATED: join(root, 'mktemp-created'),
    },
  });
  assert.ifError(result.error);
  const temps = existsSync(join(root, 'mktemp-created'))
    ? readFileSync(join(root, 'mktemp-created'), 'utf8').trim().split('\n')
      .filter((path) => path.includes('.phantom-path.'))
    : [];
  return { bin: install, home, install, rc, result, root, temps };
}

function assertReportedInstallerFailure({ install, result, root, temps }) {
  // add_to_user_path failure is a warning, not a fatal error: the install
  // itself still completes and the failure is reported on stderr.
  assert.equal(result.status, 0, `the install must still complete\nstdout: ${result.stdout}\nstderr: ${result.stderr}`);
  assert.match(result.stderr,
    new RegExp(`could not update your shell PATH; add ${escapeRegExp(install)} manually`),
    'the failed PATH update must be reported');
  assert.match(result.stdout, /installed to /);
  for (const name of ['phantom', 'phantom-mcp']) {
    assert.ok(existsSync(join(install, name)), `${name} is still installed`);
  }
  assert.equal(temps.length, 2,
    'the PATH-update temporary files must have been created before the failure');
  for (const path of temps) {
    assert.equal(existsSync(path), false,
      `temporary sibling must be removed after failure: ${basename(path)}`);
  }
  assert.deepEqual(
    readdirSync(root, { recursive: true })
      .filter((entry) => basename(entry).startsWith('.phantom-path.')),
    [],
    'no PATH-update temporary file may survive anywhere after a failed update');
}

for (const [file, installer] of Object.entries(copies)) {
  test(`${file} warns and preserves the startup file when its backup copy fails`, (t) => {
    const run = runInstaller(t, installer, { seam: 'snapshot-copy', rcState: 'file' });
    assertReportedInstallerFailure(run);
    assert.equal(readFileSync(run.rc, 'utf8'), original, 'startup file bytes unchanged');
    assert.equal(lstatSync(run.rc).mode & 0o777, 0o600, 'startup file mode unchanged');
    assert.deepEqual(readdirSync(run.home), ['.bashrc'], 'HOME holds only the startup file');
  });

  test(`${file} warns and removes the PATH-update temporary files when the candidate move fails`, (t) => {
    const run = runInstaller(t, installer, { seam: 'move', rcState: 'file' });
    assertReportedInstallerFailure(run);
    assert.equal(readFileSync(run.rc, 'utf8'), original, 'startup file bytes unchanged');
    assert.deepEqual(readdirSync(run.home), ['.bashrc'], 'HOME holds only the startup file');
  });

  test(`${file} warns and removes the PATH-update temporary files when the startup file is edited mid-update`, (t) => {
    const run = runInstaller(t, installer, { seam: 'rc-modified', rcState: 'file' });
    assertReportedInstallerFailure(run);
    assert.equal(readFileSync(run.rc, 'utf8'), `${original}${racedAppend}`,
      'the concurrent edit is left in place');
  });

  test(`${file} warns and removes the PATH-update temporary files when a startup file appears mid-update`, (t) => {
    const run = runInstaller(t, installer, { seam: 'rc-appeared', rcState: 'absent' });
    assertReportedInstallerFailure(run);
    assert.equal(readFileSync(run.rc, 'utf8'), racedArrival,
      'the arrived startup file is left in place');
    assert.deepEqual(readdirSync(run.home), ['.bashrc'], 'HOME holds only the arrived startup file');
  });

  test(`${file} warns and removes the PATH-update temporary files when the post-move validation cannot confirm the update`, (t) => {
    const run = runInstaller(t, installer, { seam: 'post-move', rcState: 'file' });
    assertReportedInstallerFailure(run);
    assert.equal(readFileSync(run.rc, 'utf8'), original,
      'the original startup file is restored after a failed post-move validation');
    assert.deepEqual(readdirSync(run.home), ['.bashrc'], 'HOME holds only the startup file')
  });
}
