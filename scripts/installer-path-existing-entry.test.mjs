import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';

// A startup file that already wires Phantom's bin dir must be left exactly as
// it is, and the user's other PATH entries must survive untouched. The file
// here is written by hand (not by a first installer run) so the test pins the
// on-disk format the installer has to recognize: the marker line, the PATH
// line, and unrelated PATH lines both before and after the managed block.
const copies = {
  'scripts/install.sh': resolve(import.meta.dirname, 'install.sh'),
  'apps/web/public/install.sh': resolve(import.meta.dirname, '..', 'apps', 'web', 'public', 'install.sh'),
};

// Same extraction as installer-path-idempotence.test.mjs: run the shipped text.
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

for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  for (const [name, config] of Object.entries(shells)) {
    test(`${file} leaves an existing ${name} PATH entry alone and keeps unrelated PATH entries`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-existing-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      const rc = config.rc(home);
      mkdirSync(dirname(rc), { recursive: true });
      mkdirSync(bin, { recursive: true });

      const other = (p) => (name === 'fish' ? `set -gx PATH "${p}" $PATH` : `export PATH="${p}:$PATH"`);
      const original = [
        '# user shell config',
        other('/opt/tools/bin'),
        '',
        marker,
        config.line(bin),
        '',
        other('/home/user/.local/bin'),
        `export PATH_NOTE="${bin}-lookalike"`,
        '',
      ].join('\n');
      writeFileSync(rc, original, { mode: 0o600 });

      const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
        encoding: 'utf8',
        timeout: 30000,
        env: { HOME: home, SHELL: config.shell, PATH: '/usr/bin:/bin' },
      });
      assert.ifError(result.error);
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, /already wired into/);
      assert.doesNotMatch(result.stdout, /added .* to PATH/);

      const after = readFileSync(rc, 'utf8');
      assert.equal(after, original, 'the startup file is byte-for-byte unchanged');
      const lines = after.split('\n');
      assert.equal(lines.filter((l) => l === config.line(bin)).length, 1, 'the entry is not duplicated');
      assert.equal(lines.filter((l) => l === marker).length, 1, 'the marker is not duplicated');
      for (const p of ['/opt/tools/bin', '/home/user/.local/bin']) {
        assert.ok(lines.includes(other(p)), `unrelated PATH entry ${p} is preserved`);
      }
    });
  }
}
