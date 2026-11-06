import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import test from 'node:test';

// Both HOME (where the shell configuration lives) and the install directory
// (the PATH entry itself) contain spaces. The shell configuration must gain
// exactly one quoted entry for the whole spaced directory, a rerun must leave
// it byte-identical, and no file may appear at a path produced by splitting
// either directory on whitespace. Runs the real mktemp, cp, mv and cmp.
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

const harness = (source, file) => ['set -euo pipefail', 'umask 077',
  ...['say', 'file_identity', 'file_link_count', 'add_to_user_path']
    .map((name) => extractFunction(source, name, file)),
  'add_to_user_path "$1"',
].join('\n');

const shells = {
  bash: { shell: '/bin/bash', rc: ['.bashrc'], line: (bin) => `export PATH="${bin}:$PATH"` },
  zsh: { shell: '/bin/zsh', rc: ['.zshrc'], line: (bin) => `export PATH="${bin}:$PATH"` },
  fish: { shell: '/usr/bin/fish', rc: ['.config', 'fish', 'config.fish'], line: (bin) => `set -gx PATH "${bin}" $PATH` },
};

for (const [file, installer] of Object.entries(copies)) {
  const script = harness(readFileSync(installer, 'utf8'), file);
  for (const [name, cfg] of Object.entries(shells)) {
    test(`${file} adds a spaced install dir to ${name} PATH once`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-spaced-bin-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'my home dir');
      const bin = join(root, 'live dir', 'phantom bin');
      const decoys = ['my', 'home', 'dir', 'live', 'phantom', 'bin'].map((d) => join(root, d));
      for (const dir of [home, bin, ...decoys]) mkdirSync(dir, { recursive: true });
      const rc = join(home, ...cfg.rc);
      const block = `\n# phantom-secrets PATH\n${cfg.line(bin)}\n`;
      const run = () => spawnSync('/bin/bash', ['-c', script, 'path-test', bin], {
        encoding: 'utf8', timeout: 30000, cwd: root,
        env: { HOME: home, SHELL: cfg.shell, PATH: '/usr/bin:/bin' },
      });

      let result = run();
      assert.ifError(result.error);
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, /added .* to PATH/);
      assert.equal(readFileSync(rc, 'utf8'), block);

      result = run();
      assert.ifError(result.error);
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, /already wired into/);
      assert.equal(readFileSync(rc, 'utf8'), block, 'rerun left the configuration byte-identical');

      for (const decoy of decoys) {
        assert.deepEqual(readdirSync(decoy), [], `${basename(decoy)} was never written to`);
      }
      assert.deepEqual(readdirSync(dirname(rc)).filter((n) => n.startsWith('.phantom-path.')), []);
    });
  }
}
