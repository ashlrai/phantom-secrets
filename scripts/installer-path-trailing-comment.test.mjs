import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { pathUpdateHarness } from './lib/installer-path-harness.mjs';

// A comment that is the last thing in a startup file (a full-line comment or an
// inline comment on the final command, with or without a final newline) must
// stay byte-for-byte unchanged by the PATH update. The managed block is
// appended after it, and a repeat run, even when the user's own trailing
// comment sits after the block, rewrites nothing.
const copies = {
  'scripts/install.sh': resolve(import.meta.dirname, 'install.sh'),
  'apps/web/public/install.sh': resolve(import.meta.dirname, '..', 'apps', 'web', 'public', 'install.sh'),
};


const marker = '# phantom-secrets PATH';
const shells = {
  bash: { shell: '/bin/bash', rc: (h) => join(h, '.bashrc'), line: (b) => `export PATH="${b}:$PATH"` },
  zsh: { shell: '/bin/zsh', rc: (h) => join(h, '.zshrc'), line: (b) => `export PATH="${b}:$PATH"` },
  fish: { shell: '/usr/bin/fish', rc: (h) => join(h, '.config', 'fish', 'config.fish'),
    line: (b) => `set -gx PATH "${b}" $PATH` },
};
const trailers = {
  'full-line comment': '# end of my config',
  'inline comment on the last command': 'export KEEP=yes # keep me last',
};

for (const [file, installer] of Object.entries(copies)) {
  const source = readFileSync(installer, 'utf8');
  const harness = pathUpdateHarness(source, file);

  for (const [shellName, config] of Object.entries(shells)) {
    for (const [kind, trailer] of Object.entries(trailers)) {
      for (const [ending, eol] of [['final newline', '\n'], ['no final newline', '']]) {
        test(`${file} keeps a trailing ${kind} intact in a ${shellName} file (${ending})`, (t) => {
          const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-trailing-')));
          t.after(() => rmSync(root, { recursive: true, force: true }));
          const home = join(root, 'home');
          const bin = join(root, 'live', 'bin');
          const rc = config.rc(home);
          mkdirSync(dirname(rc), { recursive: true });
          mkdirSync(bin, { recursive: true });
          const original = Buffer.from(`# top\n${trailer}${eol}`);
          writeFileSync(rc, original, { mode: 0o600 });
          const run = () => spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
            encoding: 'utf8', timeout: 30000,
            env: { HOME: home, SHELL: config.shell, PATH: '/usr/bin:/bin' },
          });

          const first = run();
          assert.ifError(first.error);
          assert.equal(first.status, 0, first.stderr);
          assert.match(first.stdout, /added .* to PATH/);
          const updated = readFileSync(rc);
          assert.ok(updated.subarray(0, original.length).equals(original),
            'the trailing comment bytes are unchanged');
          assert.equal(updated.subarray(original.length).toString(),
            `\n${marker}\n${config.line(bin)}\n`);

          // The user adds a new trailing comment after the managed block.
          const edited = Buffer.concat([updated, Buffer.from(`${trailer}${eol}`)]);
          writeFileSync(rc, edited);
          const second = run();
          assert.ifError(second.error);
          assert.equal(second.status, 0, second.stderr);
          assert.match(second.stdout, /already wired into/);
          assert.deepEqual(readFileSync(rc), edited, 'repeat run leaves the file untouched');
        });
      }
    }
  }
}
