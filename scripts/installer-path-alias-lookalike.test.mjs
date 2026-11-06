import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

// Edge cases for alias preservation in add_to_user_path: an alias that merely
// *mentions* the managed marker or the install dir must not be mistaken for the
// managed block (only an exact marker line counts), and an alias that is the
// last line with no trailing newline must keep every byte while the managed
// block lands after it. A second run must be a byte-for-byte no-op.
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
const cases = {
  'an alias mentioning the marker text': (bin) =>
    Buffer.from(`alias note='echo ${marker}' # ${marker} ${bin}\n`),
  'an alias that is the last line without a newline': () => Buffer.from('alias ll="ls -la"\t '),
};

for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  for (const [name, makeOriginal] of Object.entries(cases)) {
    test(`${file} appends the PATH block and keeps ${name} byte-for-byte`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-alias-lookalike-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      mkdirSync(home, { recursive: true });
      mkdirSync(bin, { recursive: true });
      const rc = join(home, '.bashrc');
      const original = makeOriginal(bin);
      writeFileSync(rc, original, { mode: 0o600 });
      const run = () => spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
        encoding: 'utf8', timeout: 30000, env: { HOME: home, SHELL: '/bin/bash', PATH: '/usr/bin:/bin' },
      });

      const first = run();
      assert.ifError(first.error);
      assert.equal(first.status, 0, first.stderr);
      assert.match(first.stdout, /added .* to PATH/, 'a lookalike line is not the managed block');
      const updated = readFileSync(rc);
      assert.ok(updated.subarray(0, original.length).equals(original), 'original bytes unchanged at their offsets');
      const tail = updated.subarray(original.length).toString('utf8');
      assert.ok(tail.endsWith(`\n${marker}\nexport PATH="${bin}:$PATH"\n`), `managed block appended, got ${JSON.stringify(tail)}`);

      const second = run();
      assert.equal(second.status, 0, second.stderr);
      assert.match(second.stdout, /already wired into/);
      assert.ok(readFileSync(rc).equals(updated), 'repeat run leaves all bytes unchanged');
    });
  }
}
