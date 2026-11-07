import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
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
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

// An initially empty shell configuration has two real shapes: no startup file
// at all (first install on a fresh account) and a zero-byte startup file
// (`touch ~/.zshrc`). installer-path-empty-file.test.mjs pins the byte-exact
// result of the second shape; this file covers both shapes and adds the
// acceptance the user actually cares about — the written entry must be
// *usable*, not just present. A real `phantom` executable stub is placed in
// the install directory, the resulting startup file is sourced the way the
// installer's own message instructs (`source $rc`), and `command -v phantom`
// must resolve to that stub. The shipped add_to_user_path is extracted
// verbatim and run directly, once per installer copy.
const installers = {
  'scripts/install.sh': new URL('install.sh', import.meta.url),
  'apps/web/public/install.sh': new URL('../apps/web/public/install.sh', import.meta.url),
};

const marker = '# phantom-secrets PATH';
const shells = {
  bash: { shell: '/bin/bash', rc: (h) => join(h, '.bashrc'), line: (b) => `export PATH="${b}:$PATH"` },
  zsh: { shell: '/bin/zsh', rc: (h) => join(h, '.zshrc'), line: (b) => `export PATH="${b}:$PATH"` },
  fish: {
    shell: '/usr/bin/fish',
    rc: (h) => join(h, '.config', 'fish', 'config.fish'),
    line: (b) => `set -gx PATH "${b}" $PATH`,
  },
};

// "Empty" configurations: `absent` never creates the startup file (for fish,
// not even its ~/.config/fish parent), `zeroed` creates it at zero bytes.
const empties = {
  absent: (rc) => assert.equal(existsSync(rc), false, 'fixture must start without a startup file'),
  zeroed: (rc) => {
    mkdirSync(dirname(rc), { recursive: true });
    writeFileSync(rc, '', { mode: 0o600 });
    assert.equal(statSync(rc).size, 0, 'fixture must start as a zero-byte file');
  },
};

function extractFunction(source, name, file) {
  const start = source.indexOf(`${name}()`);
  assert.ok(start >= 0, `${file}: locate ${name}`);
  const lineEnd = source.indexOf('\n', start);
  if (source.slice(start, lineEnd).trimEnd().endsWith('}')) return source.slice(start, lineEnd + 1);
  const end = source.indexOf('\n}\n', start);
  assert.ok(end > start, `${file}: locate end of ${name}`);
  return source.slice(start, end + 3);
}

function run(harness, config, home, bin) {
  const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
    encoding: 'utf8',
    timeout: 30000,
    env: { HOME: home, SHELL: config.shell, PATH: '/usr/bin:/bin' },
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  return result;
}

// A startup file earns the "usable" claim only if sourcing it — exactly what
// the installer tells the user to run — puts the install directory on PATH
// and resolves a real `phantom` there. The bash/zsh leg writes POSIX syntax,
// so /bin/bash (the always-present harness interpreter) can source it; the
// target shell's own source check is additive coverage that runs only when
// that shell resolves on PATH (macOS ships zsh; CI ships neither zsh nor
// fish). The fish leg's native check uses the same gate; when fish is absent
// the entry is still proven usable by extracting its directory operand and
// resolving `phantom` through a POSIX PATH prepend, which is the exact
// semantics of `set -gx PATH <dir> $PATH`.
//
// Two stubs live in the fixture bin dir: `phantom` proves the product binary
// name resolves, and `probe` — an identical script — is what the native
// zsh/fish source checks look up. Hardened hosts may policy-block executing
// an arbitrary test stub named `phantom` (zsh's stricter lookup then reports
// it not-found); `probe` exercises the same written PATH entry without
// depending on the host's view of that particular name.
function shellExists(name) {
  const probe = spawnSync(name, ['--version'], { timeout: 10000 });
  return !probe.error && probe.status === 0;
}

function resolvePhantom(shellArgv) {
  const result = spawnSync(shellArgv[0], shellArgv.slice(1), {
    encoding: 'utf8',
    timeout: 30000,
    env: { PATH: '/usr/bin:/bin' },
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, `${shellArgv[0]} source-and-resolve: ${result.stderr}`);
  return result.stdout.trim();
}

function assertUsableEntry(rc, shellName, bin, line) {
  const stub = join(bin, 'phantom');
  const probeStub = join(bin, 'probe');
  // Control: without the entry, nothing on the base PATH shadows the stubs.
  const before = spawnSync('/bin/bash', ['-c', 'command -v phantom; command -v probe'], {
    encoding: 'utf8', timeout: 30000, env: { PATH: '/usr/bin:/bin' },
  });
  assert.equal(before.stdout.trim(), '', 'base PATH must not already provide the stubs');

  if (shellName === 'fish') {
    const match = line.match(/^set -gx PATH "([^"]+)" \$PATH$/);
    assert.ok(match, 'fish PATH line must carry a quoted directory operand');
    assert.equal(match[1], bin);
    if (shellExists('fish')) {
      assert.equal(
        resolvePhantom(['fish', '-c', 'source $argv[1]; command -v probe', rc]), probeStub,
        'a fresh fish shell sourcing the file must resolve the stub');
    }
    // Emulated prepend proves the written directory operand usable even where
    // no fish binary exists; byte-exactness above already pins the syntax.
    assert.equal(
      resolvePhantom(['/bin/bash', '-c', 'PATH="$1:$PATH"; command -v phantom', 'probe', match[1]]), stub,
      'the fish PATH operand must resolve the stub through a prepend');
    return;
  }

  assert.equal(
    resolvePhantom(['/bin/bash', '-c', '. "$1" >/dev/null; command -v phantom', 'probe', rc]), stub,
    `sourcing the ${shellName} startup file must resolve the stub`);
  const native = { zsh: 'zsh' }[shellName];
  if (native && shellExists(native)) {
    assert.equal(
      resolvePhantom([native, '-c', 'source "$1" >/dev/null; command -v probe', 'probe', rc]), probeStub,
      `a fresh ${native} shell sourcing the file must resolve the stub`);
  }
}

for (const [label, url] of Object.entries(installers)) {
  const source = readFileSync(fileURLToPath(url), 'utf8');
  const harness = ['set -euo pipefail', 'umask 077',
    ...['say', 'file_identity', 'file_link_count', 'add_to_user_path']
      .map((n) => extractFunction(source, n, label)),
    'add_to_user_path "$1"'].join('\n');

  for (const [shellName, config] of Object.entries(shells)) {
    for (const [emptyName, makeEmpty] of Object.entries(empties)) {
      test(`${label} writes one usable PATH entry into an initially empty (${emptyName}) ${shellName} configuration`, (t) => {
        const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-emptycfg-')));
        t.after(() => rmSync(root, { recursive: true, force: true }));
        const home = join(root, 'home');
        const bin = join(root, 'live', 'bin');
        const rc = config.rc(home);
        mkdirSync(home, { recursive: true });
        mkdirSync(bin, { recursive: true });
        // Real executables the written entry must make resolvable.
        for (const name of ['phantom', 'probe']) {
          writeFileSync(join(bin, name), '#!/bin/sh\necho ok\n', { mode: 0o755 });
        }
        makeEmpty(rc);

        const first = run(harness, config, home, bin);
        assert.match(first.stdout, /added .* to PATH/);

        const wired = readFileSync(rc, 'utf8');
        assert.equal(wired, `\n${marker}\n${config.line(bin)}\n`,
          'the whole configuration is the managed block, one entry per line');
        assert.equal(wired.split('\n').filter((l) => l === marker).length, 1,
          'exactly one installer-managed PATH marker');
        assert.equal(wired.split('\n').filter((l) => l === config.line(bin)).length, 1,
          'exactly one installer PATH entry');
        assert.equal(statSync(rc).mode & 0o777, 0o600, 'startup file is private');

        assertUsableEntry(rc, shellName, bin, config.line(bin));

        // A repeat update must keep the single usable entry, not stack a second.
        const second = run(harness, config, home, bin);
        assert.match(second.stdout, /already wired into/);
        assert.equal(readFileSync(rc, 'utf8'), wired, 'repeat update leaves the file unchanged');
        assert.deepEqual(
          readdirSync(dirname(rc)).filter((n) => n.startsWith('.phantom-path.')),
          [], 'no PATH-update temporary files remain beside the startup file');
      });
    }
  }
}

// The usability check is only worth keeping if it fails on a wrong entry: a
// PATH line naming a directory without the executables must be rejected.
test('the usable-entry check rejects an entry pointing at a directory without phantom', (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-emptycfg-guard-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const bin = join(root, 'bin');
  const other = join(root, 'other');
  mkdirSync(bin);
  mkdirSync(other);
  for (const name of ['phantom', 'probe']) {
    writeFileSync(join(bin, name), '#!/bin/sh\necho ok\n', { mode: 0o755 });
  }
  const rc = join(root, '.bashrc');
  writeFileSync(rc, `\n${marker}\nexport PATH="${other}:$PATH"\n`, { mode: 0o600 });
  assert.throws(() => assertUsableEntry(rc, 'bash', bin, `export PATH="${other}:$PATH"`));

  const fishRc = join(root, 'config.fish');
  writeFileSync(fishRc, `\n${marker}\nset -gx PATH "${other}" $PATH\n`, { mode: 0o600 });
  assert.throws(() => assertUsableEntry(fishRc, 'fish', bin, `set -gx PATH "${other}" $PATH`));
});

// The mode assertion matters as much as the entry itself: a startup file
// another user could rewrite is not a usable PATH entry, it is a persistence
// vector, so the update must leave the file owner-only on both empty shapes.
test('the usable-entry check rejects a missing stub executable', (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-emptycfg-nostub-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const bin = join(root, 'bin');
  mkdirSync(bin);
  const rc = join(root, '.bashrc');
  const line = `export PATH="${bin}:$PATH"`;
  writeFileSync(rc, `\n${marker}\n${line}\n`, { mode: 0o600 });
  assert.throws(() => assertUsableEntry(rc, 'bash', bin, line));
});
