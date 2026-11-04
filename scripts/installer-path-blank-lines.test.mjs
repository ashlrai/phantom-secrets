import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

// The PATH update appends to a candidate copy of the startup file, so every
// pre-existing line (blank ones included) must stay where it was, in order.
// The shipped add_to_user_path is extracted verbatim and run against files
// whose blank lines are leading, doubled, whitespace-only, or trailing.
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

const shapes = [
  ['leading blank lines', '\n\n# first\nexport A=1\n'],
  ['consecutive blank lines between content', 'export A=1\n\n\n\nexport B=2\n'],
  ['whitespace-only blank lines', 'export A=1\n  \n\t\nexport B=2\n'],
  ['trailing blank lines', 'export A=1\n\n\n'],
  ['only blank lines', '\n\n\n'],
  ['CRLF blank lines', 'export A=1\r\n\r\n\r\nexport B=2\r\n'],
];

function extractFunction(source, name) {
  const start = source.indexOf(`${name}()`);
  assert.ok(start >= 0, `locate ${name}`);
  const lineEnd = source.indexOf('\n', start);
  if (source.slice(start, lineEnd).trimEnd().endsWith('}')) return source.slice(start, lineEnd + 1);
  const end = source.indexOf('\n}\n', start);
  assert.ok(end > start, `locate end of ${name}`);
  return source.slice(start, end + 3);
}

for (const [label, url] of Object.entries(installers)) {
  const source = readFileSync(fileURLToPath(url), 'utf8');
  const harness = ['set -euo pipefail', 'umask 077',
    ...['say', 'file_identity', 'file_link_count', 'add_to_user_path']
      .map((n) => extractFunction(source, n)),
    'add_to_user_path "$1"'].join('\n');
  for (const [shellName, cfg] of Object.entries(shells)) {
    for (const [shape, text] of shapes) {
      test(`${label} keeps blank lines in order in a ${shellName} file with ${shape}`, (t) => {
        const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-blank-')));
        t.after(() => rmSync(root, { recursive: true, force: true }));
        const home = join(root, 'home');
        const bin = join(root, 'live', 'bin');
        const rc = cfg.rc(home);
        mkdirSync(dirname(rc), { recursive: true });
        mkdirSync(bin, { recursive: true });
        writeFileSync(rc, text, { mode: 0o600 });

        const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
          encoding: 'utf8',
          timeout: 30000,
          env: { HOME: home, SHELL: cfg.shell, PATH: '/usr/bin:/bin' },
        });
        assert.ifError(result.error);
        assert.equal(result.status, 0, result.stderr);

        const updated = readFileSync(rc, 'utf8');
        assert.ok(updated.startsWith(text), 'original bytes are an untouched prefix');
        assert.equal(updated, `${text}\n${marker}\n${cfg.line(bin)}\n`);
        const blanks = (s) => s.split('\n').flatMap((l, i) => (l.trim() === '' ? [i] : []));
        const before = blanks(text);
        assert.deepEqual(blanks(updated).slice(0, before.length), before,
          'every original blank line keeps its position and order');
      });
    }
  }
}
