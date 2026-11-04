import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

// An initially empty shell startup configuration — a file that exists but is
// zero bytes (e.g. `touch ~/.zshrc`), or no file at all — must get exactly one
// managed PATH block: marker and PATH line on their own lines, nothing else
// added or lost, private mode, a repeat update a no-op, and the resulting file
// parseable by the shell that will read it.
// The shipped add_to_user_path is extracted verbatim and run directly.
const installers = {
  'scripts/install.sh': new URL('install.sh', import.meta.url),
  'apps/web/public/install.sh': new URL('../apps/web/public/install.sh', import.meta.url),
};

const shells = {
  bash: {
    shell: '/bin/bash', rc: (h) => join(h, '.bashrc'),
    line: (b) => `export PATH="${b}:$PATH"`, parser: ['/bin/bash', '-n'],
  },
  zsh: {
    shell: '/bin/zsh', rc: (h) => join(h, '.zshrc'),
    line: (b) => `export PATH="${b}:$PATH"`, parser: ['zsh', '-n'],
  },
  fish: {
    shell: '/usr/bin/fish',
    rc: (h) => join(h, '.config', 'fish', 'config.fish'),
    line: (b) => `set -gx PATH "${b}" $PATH`,
    parser: ['fish', '--no-execute'],
  },
};

const marker = '# phantom-secrets PATH';

function extractFunction(source, name, file) {
  const start = source.indexOf(`${name}()`);
  assert.ok(start >= 0, `${file}: locate ${name}`);
  const lineEnd = source.indexOf('\n', start);
  if (source.slice(start, lineEnd).trimEnd().endsWith('}')) return source.slice(start, lineEnd + 1);
  const end = source.indexOf('\n}\n', start);
  assert.ok(end > start, `${file}: locate end of ${name}`);
  return source.slice(start, end + 3);
}

function run(harness, config, home, bin) {
  const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
    encoding: 'utf8',
    timeout: 30000,
    env: { HOME: home, SHELL: config.shell, PATH: '/usr/bin:/bin' },
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  return result;
}

// The wired startup file must parse under the shell that will read it. Prefer
// that shell's own no-execute check when its binary is installed; otherwise
// fall back to bash -n, because the managed block is POSIX-parseable on every
// host that can run this test at all.
function checkSyntax(rc, { parser }) {
  const [cmd, ...args] = parser;
  const result = spawnSync(cmd, [...args, rc], { encoding: 'utf8' });
  const check = result.error && result.error.code === 'ENOENT'
    ? spawnSync('/bin/bash', ['-n', rc], { encoding: 'utf8' })
    : result;
  assert.ifError(check.error);
  assert.equal(check.status, 0, `${cmd} ${args.join(' ')} ${rc}: ${check.stderr}`);
}

for (const [label, url] of Object.entries(installers)) {
  const source = readFileSync(fileURLToPath(url), 'utf8');
  const harness = ['set -euo pipefail', 'umask 077',
    ...['say', 'file_identity', 'file_link_count', 'add_to_user_path']
      .map((n) => extractFunction(source, n, label)),
    'add_to_user_path "$1"'].join('\n');

  for (const [shellName, config] of Object.entries(shells)) {
    for (const state of ['empty', 'absent']) {
      test(`${label} wires an initially ${state} ${shellName} startup file once`, (t) => {
        const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-empty-')));
        t.after(() => rmSync(root, { recursive: true, force: true }));
        const home = join(root, 'home');
        const bin = join(root, 'live', 'bin');
        const rc = config.rc(home);
        if (state === 'empty') {
          mkdirSync(dirname(rc), { recursive: true });
          writeFileSync(rc, '', { mode: 0o600 });
          assert.equal(statSync(rc).size, 0);
        } else {
          // The rc parent is left absent (including fish's nested .config/fish)
          // so the update's own mkdir -p creates it.
          mkdirSync(home, { recursive: true });
          assert.equal(existsSync(rc), false);
        }
        mkdirSync(bin, { recursive: true });

        const first = run(harness, config, home, bin);
        assert.match(first.stdout, /added .* to PATH/);
        const wired = readFileSync(rc, 'utf8');
        assert.equal(wired, `\n${marker}\n${config.line(bin)}\n`,
          'only the managed block is written, each entry on its own line');
        assert.equal(wired.split('\n').filter((l) => l === marker).length, 1);
        assert.equal(statSync(rc).mode & 0o777, 0o600, 'startup file has private permissions');
        checkSyntax(rc, config);

        const second = run(harness, config, home, bin);
        assert.match(second.stdout, /already wired into/);
        assert.equal(readFileSync(rc, 'utf8'), wired, 'repeat update leaves the file unchanged');
        assert.deepEqual(
          readdirSync(dirname(rc)).filter((n) => n.startsWith('.phantom-path.')), [],
          'no PATH-update temporary files remain beside the startup file');
      });
    }
  }
}

// The syntax gate is only worth keeping if it rejects broken input: an
// unterminated quote in a startup file must trip every parser (and its
// bash -n fallback).
test('checkSyntax rejects an unparseable startup file', (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-empty-syntax-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const rc = join(root, '.bashrc');
  writeFileSync(rc, 'export PATH="/x/bin:$PATH"\necho "unclosed\n', { mode: 0o600 });
  for (const config of Object.values(shells)) {
    assert.throws(() => checkSyntax(rc, config));
  }
});
