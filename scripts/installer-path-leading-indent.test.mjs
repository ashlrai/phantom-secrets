import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';

// A startup-file line that begins with indentation (spaces, a tab, or a mix)
// must come through the PATH update byte-for-byte: the leading whitespace is
// not trimmed, normalised, or re-flowed, and the file is only ever extended by
// the managed block. Runs the shipped add_to_user_path in an isolated HOME.
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
  return source.slice(start, end + '\n}\n'.length);
}

const harnessFor = (source, file) => ['set -euo pipefail', 'umask 077',
  ...['say', 'file_identity', 'file_link_count', 'add_to_user_path']
    .map((name) => extractFunction(source, name, file)),
  'add_to_user_path "$1"',
].join('\n');

const marker = '# phantom-secrets PATH';
const shells = {
  bash: { shell: '/bin/bash', rc: (h) => join(h, '.bashrc'), line: (b) => `export PATH="${b}:$PATH"`,
    indented: ['  export EDITOR=vim', '\texport PAGER=less', ' \t  export PATH="/opt/other/bin:$PATH"', '        '] },
  zsh: { shell: '/bin/zsh', rc: (h) => join(h, '.zshrc'), line: (b) => `export PATH="${b}:$PATH"`,
    indented: ['  export EDITOR=vim', '\texport PAGER=less', ' \t  export PATH="/opt/other/bin:$PATH"', '        '] },
  fish: { shell: '/usr/bin/fish', rc: (h) => join(h, '.config', 'fish', 'config.fish'), line: (b) => `set -gx PATH "${b}" $PATH`,
    indented: ['  set -gx EDITOR vim', '\tset -gx PAGER less', ' \t  set -gx PATH /opt/other/bin $PATH', '        '] },
};

for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  for (const [name, config] of Object.entries(shells)) {
    for (const position of ['only', 'first', 'last']) {
      for (const finalNewline of [true, false]) {
        test(`${file} keeps indented ${name} lines byte-for-byte (${position}, ${finalNewline ? 'with' : 'without'} final newline)`, (t) => {
          const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-indent-')));
          t.after(() => rmSync(root, { recursive: true, force: true }));
          const home = join(root, 'home');
          const bin = join(root, 'live', 'bin');
          const rc = config.rc(home);
          mkdirSync(dirname(rc), { recursive: true });
          mkdirSync(bin, { recursive: true });
          const plain = '# plain';
          const lines = position === 'only' ? config.indented
            : position === 'first' ? [...config.indented, plain] : [plain, ...config.indented];
          const original = lines.join('\n') + (finalNewline ? '\n' : '');
          writeFileSync(rc, original, { mode: 0o600 });

          const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
            encoding: 'utf8',
            timeout: 30000,
            env: { HOME: home, SHELL: config.shell, PATH: '/usr/bin:/bin' },
          });
          assert.ifError(result.error);
          assert.equal(result.status, 0, result.stderr);

          const updated = readFileSync(rc);
          const prefix = Buffer.from(original);
          assert.ok(updated.subarray(0, prefix.length).equals(prefix),
            'the original bytes, including leading whitespace, are an exact prefix');
          assert.equal(updated.subarray(prefix.length).toString(),
            `\n${marker}\n${config.line(bin)}\n`,
            'only the managed block is appended');
        });
      }
    }
  }
}
