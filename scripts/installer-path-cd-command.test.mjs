import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';

// A user who changes directory from a startup file must keep every `cd`
// command byte-for-byte when the installer wires its bin dir into PATH: the
// update may only append the managed marker block after the original bytes.
// This drives the shipped add_to_user_path over startup files holding the
// common `cd` forms — bare `cd`, `cd ..`, `cd -`, tilde, variable and quoted
// targets — plus a `cd` whose target directory name contains the marker text,
// proving the whole-line marker check is not fooled into skipping the update.
// The shipped text of add_to_user_path is extracted and run, as in the
// sibling PATH tests.
const copies = {
  'scripts/install.sh': resolve(import.meta.dirname, 'install.sh'),
  'apps/web/public/install.sh': resolve(import.meta.dirname, '..', 'apps', 'web', 'public', 'install.sh'),
};

function extractFunction(source, name, file) {
  const start = source.indexOf(`${name}()`);
  assert.ok(start >= 0, `${file}: locate ${name}`);
  const lineEnd = source.indexOf('\n', start);
  if (source.slice(start, lineEnd).trimEnd().endsWith('}')) {
    return source.slice(start, lineEnd + 1);
  }
  const end = source.indexOf('\n}\n', start);
  assert.ok(end > start, `${file}: locate end of ${name}`);
  return source.slice(start, end + '\n}\n'.length);
}

const harnessFor = (source, file) => ['set -euo pipefail', 'umask 077',
  ...['say', 'file_identity', 'file_link_count', 'add_to_user_path']
    .map((name) => extractFunction(source, name, file)),
  'add_to_user_path "$1"',
].join('\n');

const marker = '# phantom-secrets PATH';
const shells = {
  bash: { shell: '/bin/bash', rc: (h) => join(h, '.bashrc'), line: (p) => `export PATH="${p}:$PATH"` },
  zsh: { shell: '/bin/zsh', rc: (h) => join(h, '.zshrc'), line: (p) => `export PATH="${p}:$PATH"` },
  fish: {
    shell: '/usr/bin/fish',
    rc: (h) => join(h, '.config', 'fish', 'config.fish'),
    line: (p) => `set -gx PATH "${p}" $PATH`,
  },
};

// Unrelated `cd` commands valid in bash, zsh and fish: bare, parent, previous,
// tilde, variable and quoted-space targets. None names the managed block.
const cdLines = [
  'cd',
  'cd ..',
  'cd -',
  'cd ~/projects',
  'cd "$WORKDIR"',
  "cd '/opt/some dir'",
];

function runUpdate(harness, config, home, bin) {
  const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
    encoding: 'utf8',
    timeout: 30000,
    env: { HOME: home, SHELL: config.shell, PATH: '/usr/bin:/bin' },
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  return result;
}

function assertAppendedOnly(after, original, config, bin) {
  assert.ok(after.subarray(0, original.length).equals(original),
    'original bytes are an unchanged prefix');
  assert.equal(after.subarray(original.length).toString('utf8'),
    `\n${marker}\n${config.line(bin)}\n`,
    'only the marker and PATH lines are appended');
}

for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  for (const [name, config] of Object.entries(shells)) {
    for (const [ending, tail] of Object.entries({ 'final newline': '\n', 'no final newline': '' })) {
      test(`${file} keeps unrelated cd commands byte-for-byte updating a ${name} PATH (${ending})`, (t) => {
        const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-cd-')));
        t.after(() => rmSync(root, { recursive: true, force: true }));
        const home = join(root, 'home');
        const bin = join(root, 'live', 'bin');
        const rc = config.rc(home);
        mkdirSync(dirname(rc), { recursive: true });
        mkdirSync(bin, { recursive: true });

        const original = Buffer.from(`# user config\n${cdLines.join('\n')}\nexport NOTE=1${tail}`, 'utf8');
        writeFileSync(rc, original, { mode: 0o600 });

        const result = runUpdate(harness, config, home, bin);
        assert.match(result.stdout, /added .* to PATH/);

        const after = readFileSync(rc);
        assertAppendedOnly(after, original, config, bin);
        const lines = after.toString('utf8').split('\n');
        for (const cd of cdLines) {
          assert.equal(lines.filter((l) => l === cd).length, 1,
            `unrelated cd command ${JSON.stringify(cd)} is unchanged exactly once`);
        }
      });
    }

    test(`${file} keeps a lone cd command with no final newline when updating a ${name} PATH`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-cd-lone-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      const rc = config.rc(home);
      mkdirSync(dirname(rc), { recursive: true });
      mkdirSync(bin, { recursive: true });

      const original = Buffer.from('cd "$HOME/projects"', 'utf8');
      writeFileSync(rc, original, { mode: 0o600 });

      const result = runUpdate(harness, config, home, bin);
      assert.match(result.stdout, /added .* to PATH/);
      assertAppendedOnly(readFileSync(rc), original, config, bin);
    });

    // A `cd` whose target directory name contains the marker text is not the
    // managed block: only a line that is exactly the marker proves the
    // installer already ran. The update must still append, and a repeat must
    // short-circuit on the real marker without touching the file.
    test(`${file} wires PATH past a ${name} cd whose target mentions the marker`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-cd-mention-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      const rc = config.rc(home);
      mkdirSync(dirname(rc), { recursive: true });
      mkdirSync(bin, { recursive: true });
      mkdirSync(join(home, marker), { recursive: true });

      const cdMention = `cd "$HOME/${marker}"`;
      const original = Buffer.from(`# user config\n${cdMention}\nexport NOTE=1\n`, 'utf8');
      writeFileSync(rc, original, { mode: 0o600 });

      const result = runUpdate(harness, config, home, bin);
      assert.match(result.stdout, /added .* to PATH/);
      const after = readFileSync(rc);
      assertAppendedOnly(after, original, config, bin);
      const lines = after.toString('utf8').split('\n');
      assert.equal(lines.filter((l) => l === marker).length, 1,
        'exactly one real marker line after the update');
      assert.ok(lines.includes(cdMention), 'the marker-mentioning cd command is intact');

      const second = runUpdate(harness, config, home, bin);
      assert.match(second.stdout, /already wired into/);
      assert.ok(readFileSync(rc).equals(after),
        'the repeat update leaves the file byte-for-byte unchanged');
    });
  }

  // The preserved `cd` must still evaluate: sourcing the updated bash startup
  // file lands in its target while the appended PATH line stays live.
  test(`${file} leaves a cd command working after the bash PATH update`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-cd-eval-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const home = join(root, 'home');
    const bin = join(root, 'live', 'bin');
    const projects = join(home, 'projects');
    const rc = shells.bash.rc(home);
    mkdirSync(projects, { recursive: true });
    mkdirSync(bin, { recursive: true });
    writeFileSync(rc, '# user config\ncd "$HOME/projects"\nexport NOTE=1\n', { mode: 0o600 });

    const result = runUpdate(harness, shells.bash, home, bin);
    assert.match(result.stdout, /added .* to PATH/);

    const check = spawnSync('/bin/bash', [
      '--noprofile', '--norc', '-c',
      '. "$HOME/.bashrc" && [[ "$PATH" == "$1:"* ]] && pwd -P',
      'path-test', bin,
    ], {
      encoding: 'utf8', timeout: 30000,
      env: { HOME: home, PATH: '/usr/bin:/bin' },
    });
    assert.ifError(check.error);
    assert.equal(check.status, 0, check.stderr);
    assert.equal(check.stdout.trim(), projects);
  });
}
