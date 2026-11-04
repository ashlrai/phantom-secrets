import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';

// Unrelated startup-file lines that contain spaces (leading, trailing, repeated,
// spaces inside quoted paths and values, a space-bearing PATH export of another
// tool) must survive the PATH update byte-for-byte, with or without a final
// newline. An isolated HOME holds the file; the shipped add_to_user_path runs
// against it, and a second run must change nothing.
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
const spaced = [
  '   leading spaces kept',
  'trailing spaces kept   ',
  'two  inner   gaps  here',
  '  # indented comment with  spaces  ',
  'alias gs="git status  --short"',
  'export MY_DIR="/Users/Jane Doe/My Tools/bin"',
  'cd "$HOME/Library/Application Support"',
  ' ',
  '    ',
];
const shells = {
  bash: {
    shell: '/bin/bash', rc: (h) => join(h, '.bashrc'),
    line: (b) => `export PATH="${b}:$PATH"`,
    lines: [...spaced, 'export PATH="/Users/Jane Doe/My Tools/bin:$PATH"'],
  },
  zsh: {
    shell: '/bin/zsh', rc: (h) => join(h, '.zshrc'),
    line: (b) => `export PATH="${b}:$PATH"`,
    lines: [...spaced, 'export PATH="/Users/Jane Doe/My Tools/bin:$PATH"'],
  },
  fish: {
    shell: '/usr/bin/fish', rc: (h) => join(h, '.config', 'fish', 'config.fish'),
    line: (b) => `set -gx PATH "${b}" $PATH`,
    lines: [...spaced, 'set -gx PATH "/Users/Jane Doe/My Tools/bin" $PATH'],
  },
};

for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  for (const [shellName, config] of Object.entries(shells)) {
    for (const trailing of ['\n', '']) {
      test(`${file} keeps unrelated ${shellName} lines with spaces byte-for-byte (${trailing ? 'with' : 'without'} final newline)`, (t) => {
        const root = realpathSync(mkdtempSync(join(tmpdir(), `phantom-path-spaced-${shellName}-`)));
        t.after(() => rmSync(root, { recursive: true, force: true }));
        const home = join(root, 'home');
        const bin = join(root, 'live', 'bin');
        const rc = config.rc(home);
        mkdirSync(dirname(rc), { recursive: true });
        mkdirSync(bin, { recursive: true });
        const original = Buffer.from(config.lines.join('\n') + trailing);
        writeFileSync(rc, original, { mode: 0o600 });

        const run = () => {
          const r = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
            encoding: 'utf8',
            timeout: 30000,
            env: { HOME: home, SHELL: config.shell, PATH: '/usr/bin:/bin' },
          });
          assert.ifError(r.error);
          assert.equal(r.status, 0, r.stderr);
        };

        run();
        const updated = readFileSync(rc);
        assert.ok(updated.subarray(0, original.length).equals(original),
          'original bytes are an exact prefix of the updated file');
        assert.equal(updated.subarray(original.length).toString('utf8'),
          `\n${marker}\n${config.line(bin)}\n`, 'only the managed block is appended');

        run();
        assert.ok(readFileSync(rc).equals(updated), 'a second update changes nothing');
      });
    }
  }
}
