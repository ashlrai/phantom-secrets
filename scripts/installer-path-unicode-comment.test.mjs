import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

// An unrelated Unicode comment in a shell startup file must survive the PATH
// update byte-for-byte, in any locale. Covers composed and decomposed accents,
// CJK, right-to-left text, zero-width joiners, emoji, a byte-order mark, and
// bytes that are not valid UTF-8 (a legacy Latin-1 comment).
const installers = {
  'scripts/install.sh': new URL('install.sh', import.meta.url),
  'apps/web/public/install.sh': new URL('../apps/web/public/install.sh', import.meta.url),
};

const shells = {
  bash: { shell: '/bin/bash', rc: (h) => join(h, '.bashrc'), line: (b) => `export PATH="${b}:$PATH"` },
  zsh: { shell: '/bin/zsh', rc: (h) => join(h, '.zshrc'), line: (b) => `export PATH="${b}:$PATH"` },
  fish: { shell: '/usr/bin/fish', rc: (h) => join(h, '.config', 'fish', 'config.fish'),
    line: (b) => `set -gx PATH "${b}" $PATH` },
};

const marker = '# phantom-secrets PATH';
const comment = Buffer.concat([
  Buffer.from('﻿# café café 日本語 שלום مرحبا ', 'utf8'),
  Buffer.from('👨‍👩‍👧 🚀 — über', 'utf8'),
  Buffer.from([0x20, 0xe9, 0xff, 0xfe]), // not valid UTF-8
]);

const locales = ['C', 'POSIX', 'en_US.UTF-8'];

function extractFunction(source, name, file) {
  const start = source.indexOf(`${name}()`);
  assert.ok(start >= 0, `${file}: locate ${name}`);
  const lineEnd = source.indexOf('\n', start);
  if (source.slice(start, lineEnd).trimEnd().endsWith('}')) return source.slice(start, lineEnd + 1);
  const end = source.indexOf('\n}\n', start);
  assert.ok(end > start, `${file}: locate end of ${name}`);
  return source.slice(start, end + '\n}\n'.length);
}

// Where the comment sits relative to other content in the file.
const layouts = {
  'alone, with a final newline': (c) => Buffer.concat([c, Buffer.from('\n')]),
  'alone, without a final newline': (c) => c,
  'between other lines': (c) => Buffer.concat([
    Buffer.from('export A=1\n'), c, Buffer.from('\nexport B=2\n')]),
};

for (const [label, url] of Object.entries(installers)) {
  const source = readFileSync(fileURLToPath(url), 'utf8');
  const harness = ['set -euo pipefail', 'umask 077',
    ...['say', 'file_identity', 'file_link_count', 'add_to_user_path']
      .map((name) => extractFunction(source, name, label)),
    'add_to_user_path "$1"'].join('\n');

  for (const [shellName, config] of Object.entries(shells)) {
    for (const locale of locales) {
      for (const [layout, build] of Object.entries(layouts)) {
        test(`${label} keeps a Unicode comment byte-for-byte in a ${shellName} file (${layout}, ${locale})`, (t) => {
          const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-unicode-')));
          t.after(() => rmSync(root, { recursive: true, force: true }));
          const home = join(root, 'home');
          const bin = join(root, 'live', 'bin');
          const rc = config.rc(home);
          mkdirSync(dirname(rc), { recursive: true });
          mkdirSync(bin, { recursive: true });
          const original = build(comment);
          writeFileSync(rc, original, { mode: 0o600 });

          const run = () => spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
            encoding: 'utf8',
            timeout: 30000,
            env: { HOME: home, SHELL: config.shell, PATH: '/usr/bin:/bin', LC_ALL: locale },
          });
          const first = run();
          assert.ifError(first.error);
          assert.equal(first.status, 0, first.stderr);
          assert.match(first.stdout, /added .* to PATH/);

          const updated = readFileSync(rc);
          assert.ok(updated.subarray(0, original.length).equals(original),
            'every pre-existing byte, including the Unicode comment, is unchanged');
          assert.equal(updated.subarray(original.length).toString('utf8'),
            `\n${marker}\n${config.line(bin)}\n`,
            'only the managed block is appended');
          assert.equal(updated.indexOf(comment), original.indexOf(comment),
            'the comment stays at the same offset');

          const second = run();
          assert.equal(second.status, 0, second.stderr);
          assert.match(second.stdout, /already wired into/);
          assert.ok(readFileSync(rc).equals(updated), 'a repeat update changes nothing');
        });
      }
    }
  }
}
