import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';

// An unrelated shell alias must survive the PATH update byte-for-byte, even
// when it holds characters a sloppy rewrite would mangle: quotes, `$`,
// backticks, backslashes, tabs, trailing spaces, CRLF endings, and non-ASCII
// or invalid-UTF-8 bytes. Compared as raw Buffers, not decoded strings, for
// both the append path and the already-wired no-op path.
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
  bash: { shell: '/bin/bash', rc: (h) => join(h, '.bashrc'), line: (b) => `export PATH="${b}:$PATH"`,
    alias: Buffer.from('alias gs=\'git status -sb \\\n  && echo "done: $(date) `id -un`"\'\t  \r\n') },
  zsh: { shell: '/bin/zsh', rc: (h) => join(h, '.zshrc'), line: (b) => `export PATH="${b}:$PATH"`,
    alias: Buffer.from('alias -g L=\'| less -R\' # café ✓\t \r\n') },
  fish: { shell: '/usr/bin/fish', rc: (h) => join(h, '.config', 'fish', 'config.fish'),
    line: (b) => `set -gx PATH "${b}" $PATH`,
    alias: Buffer.from('alias gs "git status -sb; echo \\"$USER\\"" \t \r\n') },
};
const invalidUtf8 = Buffer.from([0xff, 0xfe, 0x0a]);

for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  for (const [name, config] of Object.entries(shells)) {
    for (const wired of [false, true]) {
      test(`${file} keeps a ${name} alias byte-for-byte (${wired ? 'already wired' : 'PATH appended'})`, (t) => {
        const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-alias-')));
        t.after(() => rmSync(root, { recursive: true, force: true }));
        const home = join(root, 'home');
        const bin = join(root, 'live', 'bin');
        const rc = config.rc(home);
        mkdirSync(dirname(rc), { recursive: true });
        mkdirSync(bin, { recursive: true });

        const head = Buffer.concat([Buffer.from('# mine\n'), config.alias, invalidUtf8, config.alias]);
        const original = wired
          ? Buffer.concat([head, Buffer.from(`\n${marker}\n${config.line(bin)}\n`), config.alias])
          : head;
        writeFileSync(rc, original, { mode: 0o600 });

        const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
          encoding: 'utf8',
          timeout: 30000,
          env: { HOME: home, SHELL: config.shell, PATH: '/usr/bin:/bin' },
        });
        assert.ifError(result.error);
        assert.equal(result.status, 0, result.stderr);

        const after = readFileSync(rc);
        if (wired) {
          assert.match(result.stdout, /already wired into/);
          assert.ok(after.equals(original), 'the startup file is byte-for-byte unchanged');
        } else {
          assert.match(result.stdout, /added .* to PATH/);
          assert.ok(after.subarray(0, original.length).equals(original),
            'every original byte, alias included, is unchanged at its offset');
          assert.equal(after.subarray(original.length).toString('utf8'),
            `\n${marker}\n${config.line(bin)}\n`, 'only the managed block is appended');
        }
      });
    }
  }
}
