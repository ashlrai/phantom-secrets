import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import test from 'node:test';

const installer = resolve(import.meta.dirname, '../apps/web/public/install.sh');
const source = readFileSync(installer, 'utf8');
function extract(name) {
  const start = source.indexOf(`${name}()`);
  assert.ok(start >= 0, `missing ${name}`);
  const lineEnd = source.indexOf('\n', start);
  if (source.slice(start, lineEnd).trimEnd().endsWith('}')) return source.slice(start, lineEnd + 1);
  const end = source.indexOf('\n}\n', start);
  assert.ok(end > start, `missing end of ${name}`);
  return source.slice(start, end + 3);
}
const script = ['set -euo pipefail', 'umask 077',
  ...['say', 'file_identity', 'file_link_count', 'add_to_user_path'].map(extract),
  'add_to_user_path "$1"',
].join('\n');
const shells = {
  bash: { shell: '/bin/bash', rc: ['.bashrc'], line: (bin) => `export PATH="${bin}:$PATH"` },
  zsh: { shell: '/bin/zsh', rc: ['.zshrc'], line: (bin) => `export PATH="${bin}:$PATH"` },
  fish: { shell: '/usr/bin/fish', rc: ['.config', 'fish', 'config.fish'], line: (bin) => `set -gx PATH "${bin}" $PATH` },
};

for (const [name, cfg] of Object.entries(shells)) {
  for (const existing of [false, true]) {
    test(`public installer stages ${name} PATH update in a spaced parent (${existing ? 'existing' : 'new'} config)`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-space-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'shell home with spaces');
      const bin = join(root, 'bin');
      const rc = join(home, ...cfg.rc);
      const parent = dirname(rc);
      const shims = join(root, 'shims');
      const log = join(root, 'mktemp-args');
      mkdirSync(parent, { recursive: true });
      mkdirSync(bin);
      mkdirSync(shims);
      const original = 'alias ll="ls -l"\n';
      if (existing) writeFileSync(rc, original);
      // Record argument boundaries, then execute the real tool without a network.
      writeFileSync(join(shims, 'mktemp'), '#!/bin/sh\nprintf "%s\\0" "$#" "$@" >> "$TEST_MKTEMP_LOG"\nexec /usr/bin/mktemp "$@"\n');
      chmodSync(join(shims, 'mktemp'), 0o755);
      const run = () => spawnSync('/bin/bash', ['-c', script, 'path-test', bin], {
        encoding: 'utf8', timeout: 30000, cwd: root,
        env: { HOME: home, SHELL: cfg.shell, PATH: `${shims}:/usr/bin:/bin`, TEST_MKTEMP_LOG: log },
      });
      let result = run();
      assert.ifError(result.error);
      assert.equal(result.status, 0, result.stderr);
      assert.deepEqual(readFileSync(log, 'utf8').split('\0'), [
        '1', join(parent, '.phantom-path.before.XXXXXX'),
        '1', join(parent, '.phantom-path.candidate.XXXXXX'), '',
      ]);
      const expected = `${existing ? original : ''}\n# phantom-secrets PATH\n${cfg.line(bin)}\n`;
      assert.equal(readFileSync(rc, 'utf8'), expected);
      assert.deepEqual(readdirSync(parent), [basename(rc)]);
      result = run();
      assert.ifError(result.error);
      assert.equal(result.status, 0, result.stderr);
      assert.equal(readFileSync(rc, 'utf8'), expected);
      assert.deepEqual(readdirSync(parent), [basename(rc)]);
    });
  }
}
