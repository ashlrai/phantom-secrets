import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

// Unrelated comments in a startup file may carry shell-significant punctuation
// (quotes, $, backticks, backslashes, globs, &, |, ;, !, %, sed/awk
// metacharacters, non-ASCII). The PATH update must treat the file as opaque
// bytes: every pre-existing line, including those comments, survives
// byte-for-byte, and only the managed block is appended.
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
const comments = [
  '# it\'s "quoted" and `backticked` $(not run) ${NOT_EXPANDED} $HOME',
  '# back\\slash \\n \\\\ trailing\\',
  '# glob * ? [a-z] {1,2} ~ & | ; < > ( ) ! ^ % @ = + , :',
  '# s/phantom/\\&/g ; /^#/d ; \\1 & [[:space:]] .* $',
  '#no-space-comment!!!   trailing spaces   ',
  '\t# tab-indented — em dash, café, 日本語, 🚀',
  'export KEEP="a#b" # inline comment with "quotes" & $vars',
];

function extractFunction(source, name, file) {
  const start = source.indexOf(`${name}()`);
  assert.ok(start >= 0, `${file}: locate ${name}`);
  const lineEnd = source.indexOf('\n', start);
  if (source.slice(start, lineEnd).trimEnd().endsWith('}')) return source.slice(start, lineEnd + 1);
  const end = source.indexOf('\n}\n', start);
  assert.ok(end > start, `${file}: locate end of ${name}`);
  return source.slice(start, end + '\n}\n'.length);
}

for (const [label, url] of Object.entries(installers)) {
  const source = readFileSync(fileURLToPath(url), 'utf8');
  const harness = ['set -euo pipefail', 'umask 077',
    ...['say', 'file_identity', 'file_link_count', 'add_to_user_path']
      .map((name) => extractFunction(source, name, label)),
    'add_to_user_path "$1"'].join('\n');

  for (const [shellName, config] of Object.entries(shells)) {
    for (const [ending, eol] of [['LF', '\n'], ['CRLF', '\r\n'], ['no final newline', '']]) {
      test(`${label} keeps punctuation-heavy comments byte-for-byte in a ${shellName} file (${ending})`, (t) => {
        const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-punct-')));
        t.after(() => rmSync(root, { recursive: true, force: true }));
        const home = join(root, 'home');
        const bin = join(root, 'live', 'bin');
        const rc = config.rc(home);
        mkdirSync(dirname(rc), { recursive: true });
        mkdirSync(bin, { recursive: true });
        const original = Buffer.from(comments.join(ending === 'CRLF' ? '\r\n' : '\n') + eol, 'utf8');
        writeFileSync(rc, original, { mode: 0o600 });

        const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
          encoding: 'utf8',
          timeout: 30000,
          env: { HOME: home, SHELL: config.shell, PATH: '/usr/bin:/bin' },
        });
        assert.ifError(result.error);
        assert.equal(result.status, 0, result.stderr);
        assert.match(result.stdout, /added .* to PATH/);

        const updated = readFileSync(rc);
        assert.ok(updated.subarray(0, original.length).equals(original),
          'every pre-existing byte, including the comments, is unchanged');
        const added = updated.subarray(original.length).toString('utf8');
        assert.equal(added, `\n${marker}\n${config.line(bin)}\n`,
          'only the managed block is appended');
      });
    }
  }
}
