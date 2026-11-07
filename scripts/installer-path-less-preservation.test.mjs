import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const copies = [resolve(import.meta.dirname, 'install.sh'),
  resolve(import.meta.dirname, '../apps/web/public/install.sh')];

function extractFunction(source, name) {
  const start = source.indexOf(`${name}()`);
  assert.notEqual(start, -1, `missing ${name}`);
  const lineEnd = source.indexOf('\n', start);
  if (source.slice(start, lineEnd).trimEnd().endsWith('}')) return source.slice(start, lineEnd + 1);
  const end = source.indexOf('\n}\n', start);
  assert.ok(end > start, `missing end of ${name}`);
  return source.slice(start, end + 3);
}

for (const installer of copies) {
  const source = readFileSync(installer, 'utf8');
  const harness = ['set -euo pipefail', 'umask 077',
    ...['say', 'file_identity', 'file_link_count', 'add_to_user_path']
      .map((name) => extractFunction(source, name)),
    'add_to_user_path "$1"'].join('\n');
  for (const [shell, rcName] of [['bash', '.bashrc'], ['zsh', '.zshrc']]) {
    for (const ending of ['\n', '\r\n', '']) {
      test(`${installer}: preserves export LESS in ${shell} startup file (${JSON.stringify(ending)})`, (t) => {
        const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-less-')));
        t.after(() => rmSync(root, { recursive: true, force: true }));
        const home = join(root, 'home');
        const bin = join(root, 'bin');
        mkdirSync(home);
        mkdirSync(bin);
        const rc = join(home, rcName);
        const original = Buffer.from(`# user settings\nexport LESS="-FRX --shift 5"\t# pager options${ending}`);
        writeFileSync(rc, original, { mode: 0o600 });
        const expected = Buffer.concat([original, Buffer.from(`\n# phantom-secrets PATH\nexport PATH="${bin}:$PATH"\n`)]);
        const run = () => spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
          encoding: 'utf8', timeout: 30000,
          env: { HOME: home, SHELL: `/bin/${shell}`, PATH: '/usr/bin:/bin' },
        });
        const first = run();
        assert.ifError(first.error);
        assert.equal(first.status, 0, first.stderr);
        assert.match(first.stdout, /added .* to PATH/);
        assert.deepEqual(readFileSync(rc), expected);
        const second = run();
        assert.ifError(second.error);
        assert.equal(second.status, 0, second.stderr);
        assert.match(second.stdout, /already wired/);
        assert.deepEqual(readFileSync(rc), expected);
      });
    }
  }
}
