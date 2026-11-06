import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';

// Unrelated startup-file lines that contain spaces — leading and trailing runs,
// runs of several spaces inside quotes, a tab/space mix, a path with spaces,
// and a space-only line — must survive the PATH update byte-for-byte, compared
// as raw Buffers. The original bytes stay an exact prefix, the only addition is
// the managed block, and a second update (or an already-wired file) changes
// nothing. Runs the shipped add_to_user_path from both installer copies.
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
  return source.slice(start, end + 3);
}

const harnessFor = (source, file) => ['set -euo pipefail', 'umask 077',
  ...['say', 'file_identity', 'file_link_count', 'add_to_user_path']
    .map((name) => extractFunction(source, name, file)),
  'add_to_user_path "$1"',
].join('\n');

const marker = '# phantom-secrets PATH';
const shells = {
  bash: {
    shell: '/bin/bash', rc: (h) => join(h, '.bashrc'),
    line: (b) => `export PATH="${b}:$PATH"`,
    spaced: [
      '   export LEADING="three spaces before"',
      'export INNER="a    b     c"',
      'export TRAILING="x"      ',
      '\t \texport MIXED="tab and space"',
      'export SPACED_PATH="/Users/Some One/My Tools/bin"',
      '      ',
      'alias   ll="ls   -la"',
      '  # indented   comment  with   gaps  ',
    ],
  },
  zsh: {
    shell: '/bin/zsh', rc: (h) => join(h, '.zshrc'),
    line: (b) => `export PATH="${b}:$PATH"`,
    spaced: [
      '   export LEADING="three spaces before"',
      'export INNER="a    b     c"',
      'export TRAILING="x"      ',
      'setopt   no_beep   ',
      'export SPACED_PATH="/Users/Some One/My Tools/bin"',
      '      ',
      'alias   ll="ls   -la"',
      '  # indented   comment  with   gaps  ',
    ],
  },
  fish: {
    shell: '/usr/bin/fish', rc: (h) => join(h, '.config', 'fish', 'config.fish'),
    line: (b) => `set -gx PATH "${b}" $PATH`,
    spaced: [
      '   set -gx LEADING "three spaces before"',
      'set -gx INNER "a    b     c"',
      'set -gx TRAILING x      ',
      'set -gx SPACED_PATH "/Users/Some One/My Tools/bin"',
      '      ',
      'alias   ll "ls   -la"',
      '  # indented   comment  with   gaps  ',
    ],
  },
};

for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  for (const [shellName, config] of Object.entries(shells)) {
    const setup = (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), `phantom-path-spaced-${shellName}-`)));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      const rc = config.rc(home);
      mkdirSync(dirname(rc), { recursive: true });
      mkdirSync(bin, { recursive: true });
      const run = () => {
        const r = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
          encoding: 'utf8',
          timeout: 30000,
          env: { HOME: home, SHELL: config.shell, PATH: '/usr/bin:/bin' },
        });
        assert.ifError(r.error);
        assert.equal(r.status, 0, r.stderr);
        return r;
      };
      return { rc, bin, run };
    };

    for (const trailing of ['\n', '']) {
      test(`${file} keeps unrelated ${shellName} lines with spaces byte-for-byte (${trailing ? 'with' : 'without'} final newline)`, (t) => {
        const { rc, bin, run } = setup(t);
        const original = Buffer.from(config.spaced.join('\n') + trailing);
        writeFileSync(rc, original, { mode: 0o600 });

        assert.match(run().stdout, /added .* to PATH/);
        const updated = readFileSync(rc);
        assert.ok(updated.subarray(0, original.length).equals(original),
          'original bytes are an exact prefix of the updated file');
        assert.equal(updated.subarray(original.length).toString('utf8'),
          `\n${marker}\n${config.line(bin)}\n`, 'only the managed block is appended');

        run();
        assert.ok(readFileSync(rc).equals(updated), 'a second update changes nothing');
      });
    }

    test(`${file} keeps unrelated ${shellName} lines with spaces byte-for-byte when the PATH entry is already wired`, (t) => {
      const { rc, bin, run } = setup(t);
      const original = Buffer.from(`${config.spaced.join('\n')}\n${marker}\n${config.line(bin)}\n`);
      writeFileSync(rc, original, { mode: 0o600 });

      assert.match(run().stdout, /already wired into/);
      assert.ok(readFileSync(rc).equals(original), 'the whole startup file is byte-for-byte unchanged');
    });
  }
}
