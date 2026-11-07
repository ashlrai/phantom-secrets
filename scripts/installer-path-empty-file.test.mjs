import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

// A startup file that exists but is zero bytes (e.g. `touch ~/.zshrc`) must get
// exactly one managed PATH block: marker and PATH line on their own lines,
// nothing else added or lost, mode preserved, and a repeat update a no-op.
// The resulting file must also be valid shell syntax: `bash -n` parses every
// leg (the bash/zsh template is POSIX; the fish template still tokenizes as a
// simple command, so a malformed write fails there too), and each leg must
// additionally parse under its own shell's no-execute check when that shell is
// installed (macOS has zsh; fish is absent from CI runners, so those checks are
// additive rather than required). The shipped add_to_user_path is extracted
// verbatim and run directly.
const installers = {
  'scripts/install.sh': new URL('install.sh', import.meta.url),
  'apps/web/public/install.sh': new URL('../apps/web/public/install.sh', import.meta.url),
};

const shells = {
  bash: { shell: '/bin/bash', rc: (h) => join(h, '.bashrc'), line: (b) => `export PATH="${b}:$PATH"` },
  zsh: { shell: '/bin/zsh', rc: (h) => join(h, '.zshrc'), line: (b) => `export PATH="${b}:$PATH"` },
  fish: {
    shell: '/usr/bin/fish',
    rc: (h) => join(h, '.config', 'fish', 'config.fish'),
    line: (b) => `set -gx PATH "${b}" $PATH`,
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

// `bash -n` parses without executing and is always available — it is the
// harness interpreter. A target shell's own no-execute parse runs only when
// that shell resolves on PATH: CI runners ship neither zsh nor fish, while
// macOS ships zsh, so the native checks are additive coverage, never a gate
// on host tooling.
const nativeParser = {
  zsh: ['zsh', '-n'],
  fish: ['fish', '--no-execute'],
};

function assertValidShellSyntax(path, shellName) {
  const bash = spawnSync('/bin/bash', ['-n', path], { encoding: 'utf8', timeout: 30000 });
  assert.ifError(bash.error);
  assert.equal(bash.status, 0, `bash -n ${path}: ${bash.stderr}`);
  const native = nativeParser[shellName];
  if (native && !spawnSync(native[0], ['--version'], { timeout: 10000 }).error) {
    const check = spawnSync(native[0], [native[1], path], { encoding: 'utf8', timeout: 30000 });
    assert.ifError(check.error);
    assert.equal(check.status, 0, `${native[0]} ${native[1]} ${path}: ${check.stderr}`);
  }
}

for (const [label, url] of Object.entries(installers)) {
  const source = readFileSync(fileURLToPath(url), 'utf8');
  const harness = ['set -euo pipefail', 'umask 077',
    ...['say', 'file_identity', 'file_link_count', 'add_to_user_path']
      .map((n) => extractFunction(source, n, label)),
    'add_to_user_path "$1"'].join('\n');

  for (const [shellName, config] of Object.entries(shells)) {
    test(`${label} wires an initially empty ${shellName} startup file once, leaving valid ${shellName} syntax`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-empty-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      const rc = config.rc(home);
      mkdirSync(dirname(rc), { recursive: true });
      mkdirSync(bin, { recursive: true });
      writeFileSync(rc, '', { mode: 0o600 });
      assert.equal(statSync(rc).size, 0);

      const first = run(harness, config, home, bin);
      assert.match(first.stdout, /added .* to PATH/);
      const wired = readFileSync(rc, 'utf8');
      assert.equal(wired, `\n${marker}\n${config.line(bin)}\n`,
        'only the managed block is written, each entry on its own line');
      assert.equal(wired.split('\n').filter((l) => l === marker).length, 1,
        'exactly one installer-managed PATH marker');
      assert.equal(wired.split('\n').filter((l) => l === config.line(bin)).length, 1,
        'exactly one installer-managed PATH line');
      assert.equal(statSync(rc).mode & 0o777, 0o600, 'startup file mode is preserved');

      const second = run(harness, config, home, bin);
      assert.match(second.stdout, /already wired into/);
      assert.equal(readFileSync(rc, 'utf8'), wired, 'repeat update leaves the file unchanged');
      assert.deepEqual(
        readdirSync(dirname(rc)).filter((n) => n.startsWith('.phantom-path.')), [],
        'no PATH-update temporary files remain beside the startup file');

      // The resulting file — which the user is told to source — must parse.
      // The repeat update left it byte-identical, so this also proves the
      // first write itself was well-formed.
      assertValidShellSyntax(rc, shellName);
    });
  }
}

// A syntax gate is only worth keeping if it fails on broken input: a startup
// file left unparseable by the update must be rejected, not silently pass.
test('the startup-file syntax check rejects a corrupted file', (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-empty-syntax-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const rc = join(root, '.bashrc');
  writeFileSync(rc, `\n${marker}\nexport PATH="unclosed\n`, { mode: 0o600 });
  assert.throws(() => assertValidShellSyntax(rc, 'bash'), /bash -n/);
});
