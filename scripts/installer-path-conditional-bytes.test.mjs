import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';

// An unrelated shell conditional in the startup file must survive the PATH
// update byte-for-byte, compared as raw Buffers (not decoded text): nested
// if/elif/else, tabs, CRLF endings, a lone CR, a non-UTF-8 byte, and a missing
// final newline. A second update must leave the whole file untouched.
const copies = {
  'scripts/install.sh': resolve(import.meta.dirname, 'install.sh'),
  'apps/web/public/install.sh': resolve(import.meta.dirname, '..', 'apps', 'web', 'public', 'install.sh'),
};

const shells = {
  bash: { shell: '/bin/bash', rc: (h) => join(h, '.bashrc'),
    cond: 'if [ -f "$HOME/.localrc" ]; then\n\t. "$HOME/.localrc"\nelif [[ "$TERM" == xterm* ]]; then\n\tif true; then echo "x  "; fi\nelse\n\tcase "$OSTYPE" in darwin*) :;; esac\nfi' },
  zsh: { shell: '/bin/zsh', rc: (h) => join(h, '.zshrc'),
    cond: 'if [[ -n "$ZSH_VERSION" ]]; then\n\tsetopt NO_BEEP\nfi' },
  fish: { shell: '/usr/bin/fish', rc: (h) => join(h, '.config', 'fish', 'config.fish'),
    cond: 'if test -f ~/.localrc.fish\n\tsource ~/.localrc.fish\nelse if status is-interactive\n\techo hi\nend' },
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

for (const [file, installer] of Object.entries(copies)) {
  const source = readFileSync(installer, 'utf8');
  const harness = ['set -euo pipefail', 'umask 077',
    ...['say', 'file_identity', 'file_link_count', 'add_to_user_path']
      .map((name) => extractFunction(source, name, file)),
    'add_to_user_path "$1"'].join('\n');

  for (const [shellName, config] of Object.entries(shells)) {
    for (const [ending, convert] of [
      ['LF', (s) => Buffer.from(s)],
      ['CRLF with lone CR and a non-UTF-8 byte', (s) => Buffer.concat([
        Buffer.from(s.replaceAll('\n', '\r\n')), Buffer.from([0x0d, 0xe9])])],
    ]) {
      for (const trailing of ['\n', '']) {
        test(`${file} keeps an unrelated ${shellName} conditional byte-for-byte (${ending}, ${trailing ? 'with' : 'without'} final newline)`, (t) => {
          const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-cond-')));
          t.after(() => rmSync(root, { recursive: true, force: true }));
          const home = join(root, 'home');
          const bin = join(root, 'live', 'bin');
          const rc = config.rc(home);
          mkdirSync(dirname(rc), { recursive: true });
          mkdirSync(bin, { recursive: true });
          const conditional = convert(config.cond);
          const original = Buffer.concat([Buffer.from('export A=1\n'), conditional, Buffer.from(trailing)]);
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
          assert.ok(updated.includes(conditional), 'the conditional bytes are intact');
          assert.equal(updated.indexOf(conditional), updated.lastIndexOf(conditional),
            'the conditional appears once');

          run();
          assert.ok(readFileSync(rc).equals(updated), 'a second update changes nothing');
        });
      }
    }
  }
}
