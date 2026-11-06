import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import test from 'node:test';

// End-to-end with the real mktemp, cp, mv and cmp (no shims): when the shell
// configuration's parent contains spaces, the PATH update must change the
// intended file and only that file. Word-splitting the parent would send the
// update into the decoy directories named after each space-separated word, so
// they are created here and must stay untouched. HOME is also reached through
// a symlink, so the intended file is the one under the resolved spaced parent.
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

const marker = '# phantom-secrets PATH';
const shells = {
  bash: { shell: '/bin/bash', rcParts: ['.bashrc'], line: (b) => `export PATH="${b}:$PATH"` },
  zsh: { shell: '/bin/zsh', rcParts: ['.zshrc'], line: (b) => `export PATH="${b}:$PATH"` },
  fish: { shell: '/usr/bin/fish', rcParts: ['.config', 'fish', 'config.fish'], line: (b) => `set -gx PATH "${b}" $PATH` },
};
const existing = 'export EDITOR=vim\n';

for (const [file, installer] of Object.entries(copies)) {
  const script = harness(readFileSync(installer, 'utf8'), file);
  for (const [name, cfg] of Object.entries(shells)) {
    for (const [mode, hasRc, viaSymlink] of [
      ['existing startup file', true, false],
      ['new startup file', false, false],
      ['existing startup file through a symlinked HOME', true, true],
    ]) {
      test(`${file} updates only the intended ${name} startup file in a spaced parent (${mode})`, (t) => {
        const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-spaced-target-')));
        t.after(() => rmSync(root, { recursive: true, force: true }));
        const realHome = join(root, 'my home dir');
        const decoys = ['my', 'home', 'dir', 'my home'].map((d) => join(root, d));
        mkdirSync(realHome);
        for (const decoy of decoys) mkdirSync(decoy);
        const bin = join(root, 'bin');
        mkdirSync(bin);
        let home = realHome;
        if (viaSymlink) {
          home = join(root, 'link to home');
          symlinkSync(realHome, home);
        }
        const rc = join(realHome, ...cfg.rcParts);
        if (hasRc) {
          mkdirSync(dirname(rc), { recursive: true });
          writeFileSync(rc, existing, { mode: 0o600 });
        }

        const result = spawnSync('/bin/bash', ['-c', script, 'path-test', bin], {
          encoding: 'utf8',
          timeout: 30000,
          cwd: root,
          env: { HOME: home, SHELL: cfg.shell, PATH: '/usr/bin:/bin' },
        });
        assert.ifError(result.error);
        assert.equal(result.status, 0, result.stderr);

        assert.equal(readFileSync(rc, 'utf8'),
          `${hasRc ? existing : ''}\n${marker}\n${cfg.line(bin)}\n`,
          'the intended startup file gained exactly the managed block');
        assert.match(result.stdout, /added .* to PATH/);
        for (const decoy of decoys) {
          assert.deepEqual(readdirSync(decoy), [], `${basename(decoy)} was never written to`);
        }
        // No temporary file is left beside the startup file or anywhere else.
        assert.deepEqual(readdirSync(dirname(rc)).filter((n) => n.startsWith('.phantom-path.')), []);
        assert.deepEqual(readdirSync(root).sort(),
          [...decoys.map((d) => basename(d)), 'bin', basename(realHome), ...(viaSymlink ? ['link to home'] : [])].sort(),
          'nothing else appeared under the test root');
      });
    }
  }
}
