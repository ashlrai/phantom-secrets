import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';

// An unrelated `export SHELL` line in a startup file must survive the PATH
// update byte-for-byte: same bytes, same offset, exactly one occurrence, only
// the managed marker block appended. The installer picks the startup file from
// the SHELL environment variable, so these cases also prove a SHELL line
// inside the file (even one naming a different shell) never changes which file
// is updated or what is written. The shipped add_to_user_path is extracted
// from both installer copies and run in isolation.
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

// The preserved line is the second line, so a final newline, none, or CRLF
// all keep it intact wherever the appended block starts.
const lines = [
  'export SHELL=/bin/zsh',
  'export SHELL=/usr/bin/fish',
  "export SHELL='/bin/bash'",
  'export   SHELL="${SHELL:-/bin/sh}"   # keep login shell',
  'export SHELL=/bin/sh # PATH order matters',
  'export SHELL="# phantom-secrets PATH"',
];
const endings = { 'final newline': '\n', 'no final newline': '', 'CRLF final line': '\r\n' };

for (const [file, installer] of Object.entries(copies)) {
  const source = readFileSync(installer, 'utf8');
  const harness = ['set -euo pipefail', 'umask 077',
    ...['say', 'file_identity', 'file_link_count', 'add_to_user_path']
      .map((n) => extractFunction(source, n, file)),
    'add_to_user_path "$1"'].join('\n');

  for (const [name, cfg] of Object.entries(shells)) {
    for (const shellLine of lines) {
      for (const [ending, tail] of Object.entries(endings)) {
        test(`${file} keeps ${JSON.stringify(shellLine)} byte-for-byte in a ${name} file (${ending})`, (t) => {
          const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-shell-')));
          t.after(() => rmSync(root, { recursive: true, force: true }));
          const home = join(root, 'home');
          const bin = join(root, 'live', 'bin');
          const rc = cfg.rc(home);
          mkdirSync(dirname(rc), { recursive: true });
          mkdirSync(bin, { recursive: true });
          const original = Buffer.from(`# user config\n${shellLine}${tail}`, 'utf8');
          writeFileSync(rc, original, { mode: 0o600 });

          const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
            encoding: 'utf8',
            timeout: 30000,
            // A socket stdin makes some bash builds source ~/.bashrc, which
            // would run the fixture's `export SHELL` line and hide the bytes
            // under test; /dev/null keeps the startup file inert.
            stdio: ['ignore', 'pipe', 'pipe'],
            env: { HOME: home, SHELL: cfg.shell, PATH: '/usr/bin:/bin' },
          });
          assert.ifError(result.error);
          assert.equal(result.status, 0, result.stderr);
          assert.match(result.stdout, /added .* to PATH/);

          const after = readFileSync(rc);
          assert.ok(after.subarray(0, original.length).equals(original),
            'original bytes are an untouched prefix');
          assert.equal(after.subarray(original.length).toString('utf8'),
            `\n${marker}\n${cfg.line(bin)}\n`, 'only the marker and PATH lines are appended');
          const needle = Buffer.from(shellLine, 'utf8');
          const offset = original.indexOf(needle);
          assert.equal(after.indexOf(needle), offset, 'the SHELL line keeps its byte offset');
          assert.equal(after.indexOf(needle, offset + 1), -1, 'the SHELL line appears exactly once');
        });
      }
    }
  }
}
