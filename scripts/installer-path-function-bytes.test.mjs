import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

// An unrelated shell function in the startup file must survive the PATH update
// byte-for-byte, compared as raw Buffers (not decoded text), including tabs,
// CRLF line endings, a lone CR, a non-UTF-8 byte, and a missing final newline.
// A second update must leave the whole file untouched.
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

const fn = Buffer.concat([
  Buffer.from('my_func() {\r\n\techo "a\tb"  \r\n\tprintf \'%s\\n\' "caf'),
  Buffer.from([0xe9, 0x0d]),
  Buffer.from('"\r\n}'),
]);

for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  for (const trailing of ['\n', '']) {
    test(`${file} keeps an unrelated shell function byte-for-byte (${trailing ? 'with' : 'without'} final newline)`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-fnbytes-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      mkdirSync(home, { recursive: true });
      mkdirSync(bin, { recursive: true });
      const rc = join(home, '.bashrc');
      const original = Buffer.concat([Buffer.from('export A=1\n'), fn, Buffer.from(trailing)]);
      writeFileSync(rc, original, { mode: 0o600 });

      const run = () => {
        const r = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
          encoding: 'utf8',
          timeout: 30000,
          env: { HOME: home, SHELL: '/bin/bash', PATH: '/usr/bin:/bin' },
        });
        assert.ifError(r.error);
        assert.equal(r.status, 0, r.stderr);
      };

      run();
      const updated = readFileSync(rc);
      assert.ok(updated.subarray(0, original.length).equals(original),
        'original bytes are an exact prefix of the updated file');
      assert.ok(updated.includes(fn), 'the function bytes are intact');
      assert.equal(updated.indexOf(fn), updated.lastIndexOf(fn), 'the function appears once');

      run();
      assert.ok(readFileSync(rc).equals(updated), 'a second update changes nothing');
    });
  }
}
