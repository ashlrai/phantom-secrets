import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
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
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';

// A `source` (or `.`) line is the startup-file construct most likely to sit
// next to a PATH edit, and the one a regex-based rewrite is most likely to
// mangle: it can carry `$VAR`, `~`, quotes, and a trailing comment that itself
// mentions PATH. add_to_user_path must leave such a line byte-for-byte
// unchanged — same bytes at the same line index — and append only the managed
// marker block. The shipped text is extracted and run, as in the sibling PATH
// tests. A bash leg also sources the updated file so the preserved `source`
// line is proven to still evaluate, not just to still exist.
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
  bash: {
    shell: '/bin/bash',
    rc: (h) => join(h, '.bashrc'),
    line: (b) => `export PATH="${b}:$PATH"`,
    sources: [
      'source "${HOME}/.bash_extras"  # PATH extras live here',
      '. "$HOME/.cargo/env"',
    ],
  },
  zsh: {
    shell: '/bin/zsh',
    rc: (h) => join(h, '.zshrc'),
    line: (b) => `export PATH="${b}:$PATH"`,
    sources: [
      'source "${ZDOTDIR:-$HOME}/.zsh_local" # PATH extras live here',
      '. "$HOME/.cargo/env"',
    ],
  },
  fish: {
    shell: '/usr/bin/fish',
    rc: (h) => join(h, '.config', 'fish', 'config.fish'),
    line: (b) => `set -gx PATH "${b}" $PATH`,
    sources: [
      'source "$HOME/.config/fish/local.fish" # PATH extras live here',
    ],
  },
};

function runPathUpdate(harness, config, home, bin) {
  const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
    encoding: 'utf8',
    timeout: 30000,
    env: { HOME: home, SHELL: config.shell, PATH: '/usr/bin:/bin' },
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  return result;
}

const fixtureFor = (config) =>
  Buffer.from(`# user config\n${config.sources.join('\n')}\nexport EDITOR=vim\n`, 'utf8');

for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  for (const [name, config] of Object.entries(shells)) {
    test(`${file} keeps an unrelated ${name} source line unchanged when updating PATH`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-source-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      const rc = config.rc(home);
      mkdirSync(dirname(rc), { recursive: true });
      mkdirSync(bin, { recursive: true });

      const original = fixtureFor(config);
      writeFileSync(rc, original, { mode: 0o600 });

      const result = runPathUpdate(harness, config, home, bin);
      assert.match(result.stdout, /added .* to PATH/);

      const after = readFileSync(rc);
      assert.ok(after.subarray(0, original.length).equals(original),
        'every original byte, source line included, is unchanged at its offset');
      assert.equal(after.subarray(original.length).toString('utf8'),
        `\n${marker}\n${config.line(bin)}\n`, 'only the managed block is appended');

      const originalLines = original.toString('utf8').split('\n');
      const updatedLines = after.toString('utf8').split('\n');
      for (const line of config.sources) {
        const index = originalLines.indexOf(line);
        assert.ok(index >= 0, `fixture contains ${JSON.stringify(line)}`);
        assert.equal(updatedLines[index], line,
          'the source line keeps its bytes at its original line index');
        assert.equal(updatedLines.filter((l) => l === line).length, 1,
          `source line ${JSON.stringify(line)} appears exactly once`);
      }
      assert.equal(statSync(rc).mode & 0o777, 0o600,
        'the startup file keeps its permissions');
      assert.deepEqual(
        readdirSync(dirname(rc)).filter((n) => n.startsWith('.phantom-path.')),
        [],
        'no PATH-update temporary files are left behind',
      );
    });

    test(`${file} leaves a wired ${name} file with a source line byte-for-byte identical`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-source-wired-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      const rc = config.rc(home);
      mkdirSync(dirname(rc), { recursive: true });
      mkdirSync(bin, { recursive: true });

      const original = Buffer.concat([
        fixtureFor(config),
        Buffer.from(`\n${marker}\n${config.line(bin)}\n`, 'utf8'),
      ]);
      writeFileSync(rc, original, { mode: 0o600 });

      const result = runPathUpdate(harness, config, home, bin);
      assert.match(result.stdout, /already wired into/);
      assert.ok(readFileSync(rc).equals(original),
        'the no-op path leaves every byte, source line included, unchanged');
    });
  }

  test(`${file} leaves a bash source line working after the update`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-source-eval-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const home = join(root, 'home');
    const bin = join(root, 'live', 'bin');
    const rc = shells.bash.rc(home);
    mkdirSync(home, { recursive: true });
    mkdirSync(bin, { recursive: true });
    writeFileSync(join(home, '.bash_extras'),
      'PHANTOM_TEST_SOURCED=yes\nexport PATH="$HOME/extra/bin:$PATH"\n',
      { mode: 0o600 });
    writeFileSync(rc, fixtureFor(shells.bash), { mode: 0o600 });

    const result = runPathUpdate(harness, shells.bash, home, bin);
    assert.match(result.stdout, /added .* to PATH/);

    // Source the updated startup file in a clean bash: the preserved source
    // line must still evaluate, and the installer bin dir must lead PATH.
    const check = spawnSync('/bin/bash', [
      '--noprofile', '--norc', '-c',
      '. "$HOME/.bashrc" && [[ "$PHANTOM_TEST_SOURCED" == yes ]] && '
      + '[[ "$PATH" == "$1:"* ]] && [[ "$PATH" == *"$HOME/extra/bin:"* ]]',
      'path-test', bin,
    ], {
      encoding: 'utf8',
      timeout: 30000,
      env: { HOME: home, PATH: '/usr/bin:/bin' },
    });
    assert.ifError(check.error);
    assert.equal(check.status, 0, check.stderr);
  });
}
