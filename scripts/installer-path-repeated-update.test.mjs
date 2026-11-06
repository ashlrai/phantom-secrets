import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { extractFunction, pathUpdateHarness } from './lib/installer-path-harness.mjs';
import { fileURLToPath } from 'node:url';

// Re-running the installer must never stack PATH entries. Two distinct
// repeat paths reach the startup file:
//
// - A fresh installer process whose own PATH lacks the bin dir calls
//   add_to_user_path again; the shipped marker short-circuit reports
//   "already wired" and appends nothing.
// - A repeat run from a shell that already has the bin dir on PATH (the usual
//   upgrade path) skips the update before the function is even called.
//
// Both are exercised end-to-end against the real installer — offline fixture,
// full lock/staging/promote flow — so the assertion covers the shipped script,
// not an extraction. After the second run the startup file holds exactly one
// installer-managed block and is byte-for-byte identical to after the first.
const installers = {
  'scripts/install.sh': new URL('install.sh', import.meta.url),
  'apps/web/public/install.sh': new URL('../apps/web/public/install.sh', import.meta.url),
};

const marker = '# phantom-secrets PATH';
const shells = {
  bash: {
    shell: '/bin/bash',
    rc: (home) => join(home, '.bashrc'),
    pathLine: (bin) => `export PATH="${bin}:$PATH"`,
    preseed: '# user shell config\nexport EDITOR=vim\n',
  },
  zsh: {
    shell: '/bin/zsh',
    rc: (home) => join(home, '.zshrc'),
    pathLine: (bin) => `export PATH="${bin}:$PATH"`,
    preseed: '# user shell config\nexport EDITOR=vim\n',
  },
  fish: {
    shell: '/usr/bin/fish',
    rc: (home) => join(home, '.config', 'fish', 'config.fish'),
    pathLine: (bin) => `set -gx PATH "${bin}" $PATH`,
    preseed: '# user settings\nset -gx EDITOR vim\n',
  },
};

// Stub release: two binaries that answer --version, packed and checksummed
// exactly like a real asset so the offline path downloads from a directory.
function buildFixture(root) {
  const fixture = join(root, 'fixture');
  const payload = join(root, 'payload');
  mkdirSync(fixture, { recursive: true });
  mkdirSync(payload, { recursive: true });
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

function runInstaller(url, { home, shell, install, fixture, pathEnv }) {
  const env = { ...process.env };
  for (const name of ['PHANTOM_REPO', 'PHANTOM_TEST_FAIL_AFTER_PROMOTION',
    'PHANTOM_INSTALL_LOCK_WAIT_SECONDS', 'PHANTOM_INSTALL_LOCK_STALE_SECONDS',
    'PHANTOM_INSTALL_LOCK_HEARTBEAT_SECONDS']) delete env[name];
  const result = spawnSync('/bin/bash', [fileURLToPath(url)], {
    encoding: 'utf8',
    timeout: 30000,
    // stdio 'ignore' keeps stdin off a socket: node wires child stdio through
    // socketpair(), and an SSH_SOURCE_BASHRC bash treats a socket stdin as
    // remote-shell startup and sources ~/.bashrc — silently rewrites PATH
    // before the installer's own PATH check runs.
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...env,
      HOME: home,
      SHELL: shell,
      PATH: pathEnv,
      PHANTOM_INSTALL_DIR: install,
      PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
      PHANTOM_TEST_LOCAL_RELEASE_DIR: fixture,
      PHANTOM_TAG: 'v1.2.3',
    },
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /installed to /);
  return result;
}

function assertOneManagedEntry(rc, install, config, expected) {
  assert.equal(readFileSync(rc, 'utf8'), expected,
    'the second run left the startup file byte-for-byte unchanged');
  const lines = expected.split('\n');
  assert.equal(lines.filter((line) => line === marker).length, 1,
    'exactly one installer-managed PATH marker after two updates');
  assert.equal(lines.filter((line) => line.includes(install)).length, 1,
    'exactly one line names the install directory after two updates');
  assert.ok(lines.includes(config.pathLine(install)),
    'the single managed entry is the installer PATH line');
  assert.equal(statSync(rc).mode & 0o777, 0o600,
    'the startup file keeps private permissions');
  assert.deepEqual(
    readdirSync(dirname(rc)).filter((name) => name.startsWith('.phantom-path.')),
    [],
    'no PATH-update temporary files remain beside the startup file',
  );
}

// Repeat update through the marker short-circuit: the installer process runs
// with a PATH that does not contain the bin dir, so both invocations reach
// add_to_user_path; the second must recognize its own marker and append
// nothing. The pre-seeded startup file also proves user content survives
// two full installs untouched.
for (const [label, url] of Object.entries(installers)) {
  for (const [shellName, config] of Object.entries(shells)) {
    test(`${label} keeps one PATH entry when the update runs twice (${shellName}, existing startup file)`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-twice-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const fixture = buildFixture(root);
      const home = join(root, 'home');
      const install = join(root, 'live', 'bin');
      const rc = config.rc(home);
      mkdirSync(dirname(rc), { recursive: true });
      writeFileSync(rc, config.preseed, { mode: 0o600 });
      const pathEnv = '/usr/bin:/bin';

      const first = runInstaller(url, { home, shell: config.shell, install, fixture, pathEnv });
      assert.match(first.stdout, /added .* to PATH/);
      const wired = readFileSync(rc, 'utf8');
      assert.equal(wired, `${config.preseed}\n${marker}\n${config.pathLine(install)}\n`);

      // A sentinel inside the live install proves run two really re-promoted
      // a candidate instead of short-circuiting the whole install.
      writeFileSync(join(install, 'sentinel'), 'first-run');
      const second = runInstaller(url, { home, shell: config.shell, install, fixture, pathEnv });
      assert.match(second.stdout, /already wired into/);
      assert.doesNotMatch(second.stdout, /added .* to PATH/,
        'the second update must not append a second PATH block');
      assert.equal(existsSync(join(install, 'sentinel')), false,
        'the second run replaced the previous install');
      for (const name of ['phantom', 'phantom-mcp']) {
        assert.ok(existsSync(join(install, name)), `${name} is installed after the second run`);
      }
      assert.deepEqual(readdirSync(dirname(install)), ['bin'],
        'no staging, backup, or lock remains beside the second install');
      assertOneManagedEntry(rc, install, config, wired);
    });
  }
}

// Repeat update through the PATH short-circuit: the second run comes from a
// shell where the first update has already taken effect, so the installer
// sees the bin dir on PATH and never calls the update at all. The startup
// file the first run created (no pre-existing rc) still holds one entry.
for (const [label, url] of Object.entries(installers)) {
  for (const [shellName, config] of Object.entries(shells)) {
    test(`${label} keeps one PATH entry when a repeat install already has it on PATH (${shellName}, absent startup file)`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-twice-onpath-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const fixture = buildFixture(root);
      const home = join(root, 'home');
      const install = join(root, 'live', 'bin');
      const rc = config.rc(home);
      mkdirSync(home, { recursive: true });

      const first = runInstaller(url, {
        home, shell: config.shell, install, fixture, pathEnv: '/usr/bin:/bin',
      });
      assert.match(first.stdout, /added .* to PATH/);
      const wired = readFileSync(rc, 'utf8');
      assert.equal(wired, `\n${marker}\n${config.pathLine(install)}\n`);

      const second = runInstaller(url, {
        home, shell: config.shell, install, fixture,
        pathEnv: `${install}:/usr/bin:/bin`,
      });
      assert.doesNotMatch(second.stdout, /added .* to PATH|already wired into/,
        'a bin dir already on PATH skips the update entirely');
      assertOneManagedEntry(rc, install, config, wired);
    });
  }
}

// The installer's own PATH guard, extracted verbatim: after a successful
// install the script checks the live PATH for the bin dir and only calls
// add_to_user_path when it is absent. Driving that shipped tail three times
// proves the guard wiring — not just the function — leaves one managed
// entry: the second run short-circuits on the marker (bin dir off PATH) and
// the third skips the update entirely (bin dir on PATH). This path needs no
// installer run, so it also verifies where archive-extracted stubs cannot
// exec.
function extractTail(source, file) {
  const anchor = "if ! printf '%s\\n' \"$PATH\"";
  const start = source.indexOf(anchor);
  assert.ok(start >= 0, `${file}: locate the PATH update tail`);
  const end = source.indexOf('\nfi', start);
  assert.ok(end > start, `${file}: locate end of the PATH update tail`);
  return source.slice(start, end + '\nfi'.length);
}

const tailHarness = (source, file) => ['set -euo pipefail', 'umask 077',
  ...['say', 'warn', 'file_identity', 'file_link_count', 'add_to_user_path']
    .map((name) => extractFunction(source, name, file)),
  'INSTALL_DIR="$1"',
  extractTail(source, file),
].join('\n');

function runTailUpdate(harness, config, home, bin, pathEnv) {
  const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
    encoding: 'utf8',
    timeout: 30000,
    // Same socket-stdin rc-sourcing guard as runInstaller.
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { HOME: home, SHELL: config.shell, PATH: pathEnv },
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  return result;
}

for (const [label, url] of Object.entries(installers)) {
  const harness = tailHarness(readFileSync(fileURLToPath(url), 'utf8'), label);
  for (const [shellName, config] of Object.entries(shells)) {
    test(`${label} tail wiring leaves one PATH entry after repeat updates (${shellName})`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-tail-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      const rc = config.rc(home);
      mkdirSync(dirname(rc), { recursive: true });
      mkdirSync(bin, { recursive: true });
      writeFileSync(rc, config.preseed, { mode: 0o600 });

      const first = runTailUpdate(harness, config, home, bin, '/usr/bin:/bin');
      assert.match(first.stdout, /added .* to PATH/);
      const wired = readFileSync(rc, 'utf8');
      assert.equal(wired, `${config.preseed}\n${marker}\n${config.pathLine(bin)}\n`);

      const second = runTailUpdate(harness, config, home, bin, '/usr/bin:/bin');
      assert.match(second.stdout, /already wired into/);
      assert.doesNotMatch(second.stdout, /added .* to PATH/,
        'the second update must not append a second PATH block');
      assert.equal(readFileSync(rc, 'utf8'), wired,
        'the second update left the startup file byte-for-byte unchanged');

      const third = runTailUpdate(harness, config, home, bin, `${bin}:/usr/bin:/bin`);
      assert.doesNotMatch(third.stdout, /added .* to PATH|already wired into/,
        'a bin dir already on PATH skips the update entirely');
      assert.equal(readFileSync(rc, 'utf8'), wired,
        'the third update left the startup file byte-for-byte unchanged');
      assertOneManagedEntry(rc, bin, config, wired);
    });
  }
}

// Function-level: concurrent repeat updates. Two installers pointed at
// different install dirs take different locks, so their PATH updates can race
// the marker check against the atomic mv. The shipped add_to_user_path is
// extracted verbatim — same harness as installer-path-idempotence.test.mjs —
// so the exercised code is the shipped code; no installer run needed, which
// also keeps this on machines where archive-extracted stubs cannot exec.
//
// The post-move rollback lets every racer lose safely, so no winner is
// required: each attempt may only exit 0 or 1, and the file must end
// byte-exactly as the untouched preseed or the preseed plus one complete
// canonical managed block — never a partial, duplicated, or interleaved
// write. One ordinary follow-up update must then converge the file to the
// canonical wired bytes whether or not a racer already won.
const runUpdateAttempt = (harness, config, home, bin) => new Promise((resolvePromise, reject) => {
  const child = spawn('/bin/bash', ['-c', harness, 'path-test', bin], {
    // Same socket-stdin rc-sourcing guard as runInstaller.
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { HOME: home, SHELL: config.shell, PATH: '/usr/bin:/bin' },
  });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk) => { stdout += chunk; });
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  child.on('error', reject);
  child.on('close', (status) => resolvePromise({ status, stdout, stderr }));
});

for (const [label, url] of Object.entries(installers)) {
  const harness = pathUpdateHarness(readFileSync(fileURLToPath(url), 'utf8'), label);
  for (const [shellName, config] of Object.entries(shells)) {
    test(`${label} keeps one PATH entry when ${shellName} updates repeat concurrently`, async (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-concurrent-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      const rc = config.rc(home);
      mkdirSync(dirname(rc), { recursive: true });
      mkdirSync(bin, { recursive: true });
      writeFileSync(rc, config.preseed, { mode: 0o600 });
      const preseedBytes = Buffer.from(config.preseed, 'utf8');
      const wiredBytes = Buffer.from(`${config.preseed}\n${marker}\n${config.pathLine(bin)}\n`, 'utf8');

      const attempts = 6;
      const results = await Promise.all(
        Array.from({ length: attempts }, () => runUpdateAttempt(harness, config, home, bin)),
      );
      for (const result of results) {
        assert.ok(result.status === 0 || result.status === 1,
          `a repeat update may only win or lose cleanly, got ${result.status}: ${result.stderr}`);
      }

      // Every racer may lose safely under the post-move rollback, so the only
      // admissible final states are the untouched preseed or the preseed plus
      // exactly one complete canonical managed block. This exact byte
      // comparison rejects malformed, duplicated, or interleaved candidates.
      const raced = readFileSync(rc);
      assert.ok(raced.equals(preseedBytes) || raced.equals(wiredBytes),
        'concurrent updates leave the startup file as the untouched preseed or the preseed plus exactly one complete managed block');
      assert.equal(statSync(rc).mode & 0o777, 0o600,
        'the startup file keeps private permissions');
      assert.deepEqual(
        readdirSync(dirname(rc)).filter((name) => name.startsWith('.phantom-path.')),
        [],
        'losing updates cleaned their temporary files',
      );

      // One ordinary update afterwards must succeed and converge the file to
      // exactly the canonical wired bytes: a fresh wire when every racer
      // lost, a quiet already-wired no-op when one won — user bytes never
      // change on the already-wired path.
      const followUp = await runUpdateAttempt(harness, config, home, bin);
      assert.equal(followUp.status, 0, followUp.stderr);
      assert.match(followUp.stdout, /added .* to PATH|already wired into/,
        'the follow-up update reports a clean wire or an already-wired success');
      assert.ok(readFileSync(rc).equals(wiredBytes),
        'the follow-up update leaves exactly the preseed plus one canonical managed block');
      assert.equal(statSync(rc).mode & 0o777, 0o600,
        'the startup file keeps private permissions after the follow-up update');
      assert.deepEqual(
        readdirSync(dirname(rc)).filter((name) => name.startsWith('.phantom-path.')),
        [],
        'the follow-up update cleaned its temporary files',
      );
    });
  }
}
