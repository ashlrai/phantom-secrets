import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';

const installers = {
  'scripts/install.sh': new URL('install.sh', import.meta.url),
  'apps/web/public/install.sh': new URL('../apps/web/public/install.sh', import.meta.url),
};
const shells = [
  { name: 'bash', rc: '.bashrc', line: (bin) => `export PATH="${bin}:$PATH"` },
  { name: 'zsh', rc: '.zshrc', line: (bin) => `export PATH="${bin}:$PATH"` },
  { name: 'fish', rc: '.config/fish/config.fish', line: (bin) => `set -gx PATH "${bin}" $PATH` },
];

function extract(source, name) {
  const start = source.indexOf(`${name}()`);
  assert.ok(start >= 0, `missing ${name}`);
  const lineEnd = source.indexOf('\n', start);
  assert.ok(lineEnd > start, `missing first line of ${name}`);
  const end = source.slice(start, lineEnd).trimEnd().endsWith('}')
    ? lineEnd + 1 : source.indexOf('\n}\n', start) + 3;
  assert.ok(end > start, `missing end of ${name}`);
  return source.slice(start, end);
}

for (const [label, installer] of Object.entries(installers)) {
  const source = readFileSync(installer, 'utf8');
  const harness = ['set -euo pipefail', 'umask 077',
    ...['say', 'file_identity', 'file_link_count', 'add_to_user_path'].map((name) => extract(source, name)),
    'add_to_user_path "$1"'].join('\n');

  for (const shell of shells) {
    for (const ending of ['\n', '', '\r\n']) {
      test(`${label} preserves export VISUAL in ${shell.rc} with ${JSON.stringify(ending)} ending`, (t) => {
        const home = mkdtempSync(join(tmpdir(), 'phantom-visual-'));
        t.after(() => rmSync(home, { recursive: true, force: true }));
        const bin = join(home, 'bin');
        const rc = join(home, shell.rc);
        mkdirSync(bin);
        mkdirSync(dirname(rc), { recursive: true });
        // A marker mention inside a user assignment is not the managed marker.
        const original = Buffer.from(`# local settings\nexport VISUAL="editor # phantom-secrets PATH"  # keep editor${ending}`);
        writeFileSync(rc, original, { mode: 0o600 });
        const run = () => spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
          encoding: 'utf8', timeout: 30000,
          env: { HOME: home, SHELL: `/bin/${shell.name}`, PATH: '/usr/bin:/bin' },
        });
        const first = run();
        assert.ifError(first.error);
        assert.equal(first.status, 0, first.stderr);
        assert.match(first.stdout, /added .* to PATH/);
        const updated = readFileSync(rc);
        assert.deepEqual(updated, Buffer.concat([original,
          Buffer.from(`\n# phantom-secrets PATH\n${shell.line(bin)}\n`)]));
        const second = run();
        assert.ifError(second.error);
        assert.equal(second.status, 0, second.stderr);
        assert.deepEqual(readFileSync(rc), updated, 'repeat update preserves every byte');
      });
    }
  }
}
