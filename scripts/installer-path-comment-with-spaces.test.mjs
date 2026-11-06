import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';

// An unrelated plain-words comment (several spaces, in the middle of the file)
// must be unchanged, byte-for-byte, after the PATH update. Runs the shipped
// add_to_user_path from both installer copies in an isolated HOME.
const copies = {
  'scripts/install.sh': resolve(import.meta.dirname, 'install.sh'),
  'apps/web/public/install.sh': resolve(import.meta.dirname, '..', 'apps', 'web', 'public', 'install.sh'),
};

const shells = {
  bash: { shell: '/bin/bash', rc: (h) => join(h, '.bashrc'), line: (b) => `export PATH="${b}:$PATH"` },
  zsh: { shell: '/bin/zsh', rc: (h) => join(h, '.zshrc'), line: (b) => `export PATH="${b}:$PATH"` },
  fish: { shell: '/usr/bin/fish', rc: (h) => join(h, '.config', 'fish', 'config.fish'),
    line: (b) => `set -gx PATH "${b}" $PATH` },
};

const marker = '# phantom-secrets PATH';
const comment = '# my   notes: keep this   comment exactly as it is,  spaces and all  ';

function extractFunction(source, name, file) {
  const start = source.indexOf(`${name}()`);
  assert.ok(start >= 0, `${file}: locate ${name}`);
  const lineEnd = source.indexOf('\n', start);
  if (source.slice(start, lineEnd).trimEnd().endsWith('}')) return source.slice(start, lineEnd + 1);
  const end = source.indexOf('\n}\n', start);
  assert.ok(end > start, `${file}: locate end of ${name}`);
  return source.slice(start, end + 3);
}

for (const [label, path] of Object.entries(copies)) {
  const source = readFileSync(path, 'utf8');
  const harness = ['set -euo pipefail', 'umask 077',
    ...['say', 'file_identity', 'file_link_count', 'add_to_user_path']
      .map((name) => extractFunction(source, name, label)),
    'add_to_user_path "$1"'].join('\n');

  for (const [shellName, config] of Object.entries(shells)) {
    test(`${label} leaves a spaced unrelated comment byte-for-byte unchanged (${shellName})`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-comment-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      const rc = config.rc(home);
      mkdirSync(dirname(rc), { recursive: true });
      mkdirSync(bin, { recursive: true });
      const original = Buffer.from(`alias ll='ls -la'\n${comment}\nexport EDITOR=vim\n`, 'utf8');
      writeFileSync(rc, original, { mode: 0o600 });

      const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
        encoding: 'utf8',
        timeout: 30000,
        env: { HOME: home, SHELL: config.shell, PATH: '/usr/bin:/bin' },
      });
      assert.ifError(result.error);
      assert.equal(result.status, 0, result.stderr);

      const updated = readFileSync(rc);
      assert.ok(updated.subarray(0, original.length).equals(original), 'original bytes are an exact prefix');
      const commentBytes = Buffer.from(`\n${comment}\n`, 'utf8');
      assert.equal(updated.indexOf(commentBytes), original.indexOf(commentBytes), 'comment stays at its offset');
      assert.equal(updated.indexOf(commentBytes, updated.indexOf(commentBytes) + 1), -1, 'comment appears once');
      assert.equal(updated.subarray(original.length).toString('utf8'),
        `\n${marker}\n${config.line(bin)}\n`, 'only the managed block is appended');
    });
  }
}
