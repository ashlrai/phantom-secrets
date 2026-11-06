import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  chmodSync, mkdirSync, mkdtempSync, readdirSync, readFileSync,
  realpathSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

// If the PATH-update snapshot (or candidate) temp file cannot be created, the
// update must fail and leave the shell startup file byte-for-byte, mode, and
// mtime untouched, with no temp files left behind. A fake `mktemp` on PATH
// fails the matching template. The shipped add_to_user_path is extracted
// verbatim, as in installer-path-final-newline.test.mjs.
const installers = {
  'scripts/install.sh': new URL('install.sh', import.meta.url),
  'apps/web/public/install.sh': new URL('../apps/web/public/install.sh', import.meta.url),
};
const shells = {
  bash: { shell: '/bin/bash', rc: (h) => join(h, '.bashrc') },
  zsh: { shell: '/bin/zsh', rc: (h) => join(h, '.zshrc') },
  fish: { shell: '/usr/bin/fish', rc: (h) => join(h, '.config', 'fish', 'config.fish') },
};

function extractFunction(source, name) {
  const start = source.indexOf(`${name}()`);
  assert.ok(start >= 0, `locate ${name}`);
  const lineEnd = source.indexOf('\n', start);
  if (source.slice(start, lineEnd).trimEnd().endsWith('}')) return source.slice(start, lineEnd + 1);
  const end = source.indexOf('\n}\n', start);
  assert.ok(end > start, `locate end of ${name}`);
  return source.slice(start, end + 3);
}

const harness = (source) => ['set -euo pipefail', 'umask 077',
  ...['say', 'file_identity', 'file_link_count', 'add_to_user_path'].map((n) => extractFunction(source, n)),
  'add_to_user_path "$1"',
].join('\n');

const original = '# user shell config\nexport EDITOR=vim\n';

for (const [label, url] of Object.entries(installers)) {
  const script = harness(readFileSync(fileURLToPath(url), 'utf8'));
  for (const [shellName, config] of Object.entries(shells)) {
    for (const kind of ['before', 'candidate']) {
      for (const rcExists of [true, false]) {
        test(`${label} fails without touching a ${shellName} ${rcExists ? 'existing' : 'absent'} startup file when the ${kind} temp file cannot be created`, (t) => {
          const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-snapshot-fail-')));
          t.after(() => rmSync(root, { recursive: true, force: true }));
          const home = join(root, 'home');
          const fakeBin = join(root, 'fakebin');
          const bin = join(root, 'live', 'bin');
          mkdirSync(home, { recursive: true });
          mkdirSync(fakeBin);
          const realMktemp = spawnSync('/usr/bin/which', ['mktemp'], { encoding: 'utf8' }).stdout.trim();
          writeFileSync(join(fakeBin, 'mktemp'),
            `#!/bin/sh\ncase "$1" in *.phantom-path.${kind}.*) exit 1;; esac\nexec ${realMktemp} "$@"\n`);
          chmodSync(join(fakeBin, 'mktemp'), 0o755);

          const rc = config.rc(home);
          mkdirSync(dirname(rc), { recursive: true });
          let before;
          if (rcExists) {
            writeFileSync(rc, original, { mode: 0o600 });
            before = statSync(rc);
          }
          const result = spawnSync('/bin/bash', ['-c', script, 'path-test', bin], {
            encoding: 'utf8',
            timeout: 30000,
            env: { HOME: home, SHELL: config.shell, PATH: `${fakeBin}:/usr/bin:/bin` },
          });
          assert.ifError(result.error);
          assert.notEqual(result.status, 0, 'PATH update must fail');
          assert.doesNotMatch(result.stdout, /added .* to PATH/);

          const names = readdirSync(dirname(rc));
          assert.deepEqual(names.filter((n) => n.startsWith('.phantom-path.')), [],
            'no PATH-update temporary files remain');
          if (rcExists) {
            assert.equal(readFileSync(rc, 'utf8'), original, 'startup file bytes unchanged');
            const after = statSync(rc);
            assert.equal(after.mode & 0o777, 0o600);
            assert.equal(after.ino, before.ino, 'startup file not replaced');
            assert.equal(after.mtimeMs, before.mtimeMs, 'startup file not rewritten');
          } else {
            assert.ok(!names.includes(rc.split('/').pop()), 'startup file not created');
          }
        });
      }
    }
  }
}
