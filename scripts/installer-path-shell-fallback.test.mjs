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
import { basename, join, resolve } from 'node:path';
import test from 'node:test';
import { pathUpdateHarness } from './lib/installer-path-harness.mjs';

// add_to_user_path picks the startup file from `basename "${SHELL:-bash}"`:
// zsh gets ~/.zshrc, fish gets ~/.config/fish/config.fish, and every other
// result falls back to ~/.bashrc (documented as "for anything else" in
// docs/installer-path-update-reference.md). The fallback is reached two ways:
// the `${SHELL:-bash}` default when SHELL is empty — an empty shell
// configuration — and the `*)` case for names the installer does not know.
// Each fixture drives the shipped function once and then repeats it, asserting
// the resulting configuration holds the intended PATH entry exactly once, no
// other shell's startup file is created, and a bash syntax check plus a real
// source of the file put the bin directory first on PATH.
const copies = {
  'scripts/install.sh': resolve(import.meta.dirname, 'install.sh'),
  'apps/web/public/install.sh': resolve(import.meta.dirname, '..', 'apps', 'web', 'public', 'install.sh'),
};

// Same extraction as installer-path-idempotence.test.mjs: the exercised code
// is the shipped code, including its `set -euo pipefail` environment.

const harnessFor = pathUpdateHarness;

const marker = '# phantom-secrets PATH';
const exportLine = (bin) => `export PATH="${bin}:$PATH"`;
const fishLine = (bin) => `set -gx PATH "${bin}" $PATH`;

// The startup file each SHELL basename selects, mirroring the installer's own
// mapping, and the PATH line that shell's template writes.
const startupFor = (shellName, home) => (shellName === 'fish'
  ? { rc: join(home, '.config', 'fish', 'config.fish'), line: fishLine }
  : shellName === 'zsh'
    ? { rc: join(home, '.zshrc'), line: exportLine }
    : { rc: join(home, '.bashrc'), line: exportLine });

// A shellEnv of undefined leaves SHELL out of the child environment entirely;
// anything else is passed through verbatim.
function runPathUpdate(harness, shellEnv, home, bin) {
  const env = { HOME: home, PATH: '/usr/bin:/bin' };
  if (shellEnv !== undefined) env.SHELL = shellEnv;
  const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
    encoding: 'utf8',
    timeout: 30000,
    env,
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  return result;
}

const fallbackShells = [
  ['empty', ''],
  ['whitespace-only', '   '],
  ['/bin/sh', '/bin/sh'],
  ['/usr/bin/dash', '/usr/bin/dash'],
  ['/bin/ksh', '/bin/ksh'],
  ['/bin/tcsh', '/bin/tcsh'],
  ['/usr/bin/pwsh', '/usr/bin/pwsh'],
  ['nu', 'nu'],
  ['/', '/'],
];

for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  for (const [label, shellEnv] of fallbackShells) {
    test(`${file} wires the PATH entry into ~/.bashrc exactly once when SHELL is ${label}`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-fallback-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      mkdirSync(home, { recursive: true });
      mkdirSync(bin, { recursive: true });
      const rc = join(home, '.bashrc');

      const first = runPathUpdate(harness, shellEnv, home, bin);
      assert.match(first.stdout, /added .* to PATH/);

      const wired = `\n${marker}\n${exportLine(bin)}\n`;
      assert.equal(readFileSync(rc, 'utf8'), wired,
        'the fallback startup file holds only the managed PATH block');
      const lines = wired.split('\n');
      assert.equal(lines.filter((line) => line === marker).length, 1,
        'exactly one installer-managed PATH marker');
      assert.equal(lines.filter((line) => line === exportLine(bin)).length, 1,
        'exactly one installer-managed PATH line');
      assert.equal(statSync(rc).mode & 0o777, 0o600, 'startup file is private');
      assert.equal(existsSync(join(home, '.zshrc')), false, 'no zsh startup file is created');
      assert.equal(existsSync(join(home, '.config', 'fish', 'config.fish')), false,
        'no fish startup file is created');

      const second = runPathUpdate(harness, shellEnv, home, bin);
      assert.match(second.stdout, /already wired into/);
      assert.equal(readFileSync(rc, 'utf8'), wired,
        'a repeat fallback update leaves the file unchanged');
      assert.deepEqual(readdirSync(home).filter((n) => n.startsWith('.phantom-path.')), [],
        'no PATH-update temporary files remain');

      const syntax = spawnSync('/bin/bash', ['-n', rc], { encoding: 'utf8', timeout: 30000 });
      assert.ifError(syntax.error);
      assert.equal(syntax.status, 0, `bash -n ${rc}: ${syntax.stderr}`);

      // The resulting configuration must also be effective: sourcing it puts
      // the install directory first on PATH, not merely present in the text.
      const effective = spawnSync('/bin/bash', ['--noprofile', '--norc', '-c',
        '. "$HOME/.bashrc" && [ "$PATH" = "$1" ]', 'path-check', `${bin}:/usr/bin:/bin`], {
        encoding: 'utf8',
        timeout: 30000,
        env: { HOME: home, PATH: '/usr/bin:/bin' },
      });
      assert.ifError(effective.error);
      assert.equal(effective.status, 0, effective.stderr);
    });
  }
}

// An unset SHELL never reaches the `${SHELL:-bash}` default: bash assigns the
// login shell's path to SHELL at startup before the function runs, so the
// update wires whichever startup file the login shell selects. The expected
// file is predicted by asking the same interpreter what SHELL became rather
// than hardcoding a host's login shell.
for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  test(`${file} wires the login shell's startup file exactly once when SHELL is unset`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-noshell-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const home = join(root, 'home');
    const bin = join(root, 'live', 'bin');
    mkdirSync(home, { recursive: true });
    mkdirSync(bin, { recursive: true });

    const probe = spawnSync('/bin/bash', ['-c', 'printf %s "$SHELL"'], {
      encoding: 'utf8',
      timeout: 30000,
      env: { HOME: home, PATH: '/usr/bin:/bin' },
    });
    assert.ifError(probe.error);
    assert.equal(probe.status, 0, probe.stderr);
    const { rc, line } = startupFor(basename(probe.stdout || 'bash'), home);

    const first = runPathUpdate(harness, undefined, home, bin);
    assert.match(first.stdout, /added .* to PATH/);
    const wired = readFileSync(rc, 'utf8');
    assert.equal(wired, `\n${marker}\n${line(bin)}\n`);
    const lines = wired.split('\n');
    assert.equal(lines.filter((l) => l === marker).length, 1,
      'exactly one installer-managed PATH marker');
    assert.equal(lines.filter((l) => l === line(bin)).length, 1,
      'exactly one installer-managed PATH line');
    for (const other of ['.bashrc', '.zshrc', join('.config', 'fish', 'config.fish')]) {
      if (join(home, other) !== rc) {
        assert.equal(existsSync(join(home, other)), false,
          `${other} is not created when the login shell selects ${rc}`);
      }
    }

    const second = runPathUpdate(harness, undefined, home, bin);
    assert.match(second.stdout, /already wired into/);
    assert.equal(readFileSync(rc, 'utf8'), wired, 'repeat update is a no-op');
    assert.equal(statSync(rc).mode & 0o777, 0o600);
  });
}

// The fallback still merges with pre-existing ~/.bashrc content: the managed
// block is appended after the user's bytes, once.
for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  test(`${file} appends one PATH entry to a pre-existing ~/.bashrc when SHELL is empty`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-fallback-merge-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const home = join(root, 'home');
    const bin = join(root, 'live', 'bin');
    mkdirSync(home, { recursive: true });
    mkdirSync(bin, { recursive: true });
    const rc = join(home, '.bashrc');
    const original = '# user shell configuration\nexport EDITOR=vim\n';
    writeFileSync(rc, original, { mode: 0o600 });

    assert.match(runPathUpdate(harness, '', home, bin).stdout, /added .* to PATH/);
    const wired = `${original}\n${marker}\n${exportLine(bin)}\n`;
    assert.equal(readFileSync(rc, 'utf8'), wired);
    assert.equal(wired.split('\n').filter((line) => line === exportLine(bin)).length, 1);

    assert.match(runPathUpdate(harness, '', home, bin).stdout, /already wired into/);
    assert.equal(readFileSync(rc, 'utf8'), wired, 'repeat update is a no-op');
    assert.equal(statSync(rc).mode & 0o777, 0o600);
  });

  // An already-empty shell configuration file under an empty SHELL: the
  // update wires exactly one PATH entry into the zero-byte file.
  test(`${file} wires an empty ~/.bashrc exactly once when SHELL is empty`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-fallback-empty-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const home = join(root, 'home');
    const bin = join(root, 'live', 'bin');
    mkdirSync(home, { recursive: true });
    mkdirSync(bin, { recursive: true });
    const rc = join(home, '.bashrc');
    writeFileSync(rc, '', { mode: 0o600 });

    assert.match(runPathUpdate(harness, '', home, bin).stdout, /added .* to PATH/);
    const wired = `\n${marker}\n${exportLine(bin)}\n`;
    assert.equal(readFileSync(rc, 'utf8'), wired);
    const lines = wired.split('\n');
    assert.equal(lines.filter((line) => line === marker).length, 1);
    assert.equal(lines.filter((line) => line === exportLine(bin)).length, 1);
    assert.equal(statSync(rc).mode & 0o777, 0o600);
  });

  // The marker short-circuit is what keeps the entry single: a ~/.bashrc that
  // already carries the managed block is reported as wired and left untouched
  // even when reached through the fallback.
  test(`${file} leaves a marker-bearing ~/.bashrc untouched when SHELL is empty`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-fallback-wired-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const home = join(root, 'home');
    const bin = join(root, 'live', 'bin');
    mkdirSync(home, { recursive: true });
    mkdirSync(bin, { recursive: true });
    const rc = join(home, '.bashrc');
    const original = `# user shell configuration\n${marker}\nexport PATH="/earlier/bin:$PATH"\n`;
    writeFileSync(rc, original, { mode: 0o600 });

    const result = runPathUpdate(harness, '', home, bin);
    assert.match(result.stdout, /already wired into/);
    assert.doesNotMatch(result.stdout, /added .* to PATH/);
    assert.equal(readFileSync(rc, 'utf8'), original,
      'the earlier PATH entry is preserved and not duplicated');
  });
}

// Selection is exact in both directions: recognized shells wire only their
// own startup file and never create the ~/.bashrc fallback.
for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  const recognized = [
    ['/bin/zsh', '.zshrc', exportLine],
    ['zsh', '.zshrc', exportLine],
    ['/usr/bin/fish', join('.config', 'fish', 'config.fish'), fishLine],
    ['fish', join('.config', 'fish', 'config.fish'), fishLine],
  ];
  for (const [shellEnv, rcRel, line] of recognized) {
    test(`${file} with SHELL=${shellEnv} wires ${rcRel} and never the ~/.bashrc fallback`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-recognized-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      mkdirSync(home, { recursive: true });
      mkdirSync(bin, { recursive: true });
      const rc = join(home, rcRel);

      assert.match(runPathUpdate(harness, shellEnv, home, bin).stdout, /added .* to PATH/);
      const wired = readFileSync(rc, 'utf8');
      assert.equal(wired, `\n${marker}\n${line(bin)}\n`);
      assert.equal(wired.split('\n').filter((l) => l === line(bin)).length, 1,
        'exactly one PATH entry in the selected startup file');
      assert.equal(existsSync(join(home, '.bashrc')), false,
        'the fallback startup file is not created');
    });
  }
}
