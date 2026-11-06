import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';

// The PATH update rewrites the user's shell startup file. Unrelated Unicode
// comments (CJK, emoji, RTL, combining marks, NFC vs NFD) must come out
// byte-for-byte identical, even under the C locale an installer may run in.
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

const shells = {
  bash: { shell: '/bin/bash', rc: (h) => join(h, '.bashrc'), line: (b) => `export PATH="${b}:$PATH"` },
  zsh: { shell: '/bin/zsh', rc: (h) => join(h, '.zshrc'), line: (b) => `export PATH="${b}:$PATH"` },
  fish: { shell: '/usr/bin/fish', rc: (h) => join(h, '.config', 'fish', 'config.fish'), line: (b) => `set -gx PATH "${b}" $PATH` },
};

const comments = [
  '# 日本語のコメント — 設定',
  '# émoji 🚀🔐 and ünïcödé',
  '# مرحبا بالعالم עברית',
  '# nfc é vs nfd é and zero​width',
  '# phantom-secrets mentioned in prose is not the marker 🙂',
].join('\n');

for (const [file, installer] of Object.entries(copies)) {
  const source = readFileSync(installer, 'utf8');
  const harness = ['set -euo pipefail', 'umask 077',
    ...['say', 'file_identity', 'file_link_count', 'add_to_user_path'].map((n) => extractFunction(source, n, file)),
    'add_to_user_path "$1"'].join('\n');

  for (const [name, cfg] of Object.entries(shells)) {
    for (const locale of ['C', 'en_US.UTF-8']) {
      test(`${file} keeps Unicode comments byte-identical in ${name} rc (LC_ALL=${locale})`, (t) => {
        const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-unicode-')));
        t.after(() => rmSync(root, { recursive: true, force: true }));
        const home = join(root, 'home');
        const bin = join(root, 'bin');
        const rc = cfg.rc(home);
        mkdirSync(dirname(rc), { recursive: true });
        mkdirSync(bin);
        const before = Buffer.from(`${comments}\nexport EDITOR=vim\n# 末尾のコメント ✓\n`, 'utf8');
        writeFileSync(rc, before, { mode: 0o600 });

        const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
          encoding: 'utf8', timeout: 30000, cwd: root,
          env: { HOME: home, SHELL: cfg.shell, PATH: '/usr/bin:/bin', LC_ALL: locale },
        });
        assert.ifError(result.error);
        assert.equal(result.status, 0, result.stderr);

        const after = readFileSync(rc);
        const appended = Buffer.from(`\n# phantom-secrets PATH\n${cfg.line(bin)}\n`, 'utf8');
        assert.ok(after.subarray(0, before.length).equals(before),
          'every original byte, including Unicode comments, is preserved in place');
        assert.ok(after.subarray(before.length).equals(appended),
          'only the marker and PATH line are appended');
      });
    }
  }
}
