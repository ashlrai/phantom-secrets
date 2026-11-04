import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';

// When the installer adds Phantom's bin dir to a startup file that has no
// Phantom block yet, every byte already in the file must survive, including an
// unrelated export that looks a lot like the PATH line. The update may only
// append the marker and PATH lines after the original bytes. The shipped text
// of add_to_user_path is extracted and run, as in the sibling PATH tests.
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

// Unrelated export: odd spacing, quotes, a dollar sign, a tab and non-ASCII.
const unrelatedExport = 'export   GREETING=\'héllo  "world" $HOME\'\t# keep me';

// Final-line endings the original file may have: the export must survive each.
const endings = { 'final newline': '\n', 'no final newline': '', 'CRLF final line': '\r\n' };

for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  for (const [name, config] of Object.entries(shells)) {
   for (const [ending, tail] of Object.entries(endings)) {
    test(`${file} keeps an unrelated export byte-for-byte when updating a ${name} PATH (${ending})`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-unrelated-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      const rc = config.rc(home);
      mkdirSync(dirname(rc), { recursive: true });
      mkdirSync(bin, { recursive: true });

      const original = Buffer.from(`# user config\n${unrelatedExport}\nexport PATH_NOTE=1${tail}`, 'utf8');
      writeFileSync(rc, original, { mode: 0o600 });

      const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
        encoding: 'utf8',
        timeout: 30000,
        env: { HOME: home, SHELL: config.shell, PATH: '/usr/bin:/bin' },
      });
      assert.ifError(result.error);
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, /added .* to PATH/);

      const after = readFileSync(rc);
      assert.ok(after.subarray(0, original.length).equals(original), 'original bytes are an unchanged prefix');
      assert.equal(
        after.subarray(original.length).toString('utf8'),
        `\n${marker}\n${config.line(bin)}\n`,
        'only the marker and PATH lines are appended',
      );
      assert.ok(after.toString('utf8').split('\n').includes(unrelatedExport), 'the unrelated export line is intact');
    });
   }
  }
}
