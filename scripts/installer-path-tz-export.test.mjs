import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

const installers = {
  'scripts/install.sh': new URL('install.sh', import.meta.url),
  'apps/web/public/install.sh': new URL('../apps/web/public/install.sh', import.meta.url),
};

function extract(source, name) {
  const start = source.indexOf(`${name}()`);
  assert.ok(start >= 0, `missing ${name}`);
  const lineEnd = source.indexOf('\n', start);
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

  for (const [shell, rcName] of [['bash', '.bashrc'], ['zsh', '.zshrc']]) {
    for (const ending of ['\n', '']) {
      test(`${label} preserves export TZ in ${rcName} ${ending ? 'with' : 'without'} a final newline`, (t) => {
        const home = mkdtempSync(join(tmpdir(), 'phantom-tz-'));
        t.after(() => rmSync(home, { recursive: true, force: true }));
        const bin = join(home, 'bin');
        mkdirSync(bin);
        const rc = join(home, rcName);
        const original = Buffer.from(`# local settings\nexport TZ='America/New_York'  # keep timezone${ending}`);
        writeFileSync(rc, original, { mode: 0o600 });
        const run = () => spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
          encoding: 'utf8', timeout: 30000,
          env: { HOME: home, SHELL: `/bin/${shell}`, PATH: '/usr/bin:/bin' },
        });
        const first = run();
        assert.ifError(first.error);
        assert.equal(first.status, 0, first.stderr);
        assert.match(first.stdout, /added .* to PATH/);
        const updated = readFileSync(rc);
        assert.deepEqual(updated, Buffer.concat([original,
          Buffer.from(`\n# phantom-secrets PATH\nexport PATH="${bin}:$PATH"\n`)]));
        const second = run();
        assert.ifError(second.error);
        assert.equal(second.status, 0, second.stderr);
        assert.deepEqual(readFileSync(rc), updated, 'repeat update preserves every byte');
      });
    }
  }
}
