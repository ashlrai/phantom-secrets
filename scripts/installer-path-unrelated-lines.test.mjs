import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';

// The PATH update must leave unrelated shell configuration exactly as it was:
// every pre-existing startup-file line keeps its bytes, its order, and its
// line index, and the only new content is the managed marker block appended at
// the end. This drives the shipped add_to_user_path over startup files that
// mix unrelated constructs — comments, exports (including another tool's PATH
// export), aliases, blank and whitespace-only lines, multi-line functions, and
// if-blocks — then compares the result line-by-line rather than accepting a
// weaker "still contains" check. A bash leg also sources the updated file so
// the preserved lines are proven to still evaluate, not just to still exist.
const copies = {
  'scripts/install.sh': resolve(import.meta.dirname, 'install.sh'),
  'apps/web/public/install.sh': resolve(import.meta.dirname, '..', 'apps', 'web', 'public', 'install.sh'),
};

// Same extraction as installer-path-idempotence.test.mjs: run the shipped text.
function extractFunction(source, name, file) {
  const start = source.indexOf(`${name}()`);
  assert.ok(start >= 0, `${file}: locate ${name}`);
  const lineEnd = source.indexOf('\n', start);
  assert.ok(lineEnd > start, `${file}: locate end of ${name}`);
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
  bash: {
    shell: '/bin/bash',
    rc: (h) => join(h, '.bashrc'),
    line: (b) => `export PATH="${b}:$PATH"`,
    unrelated: [
      '# user shell config',
      'export EDITOR=vim',
      'export PATH="/opt/other/bin:$PATH"',
      '',
      '   ',
      'alias ll="ls -la"',
      'mkcd() {',
      '  mkdir -p "$1" && cd "$1"',
      '}',
      'if [ -f "$HOME/.localrc" ]; then',
      '  . "$HOME/.localrc"',
      'fi',
      'export TRAILING_SPACES="kept"   ',
      'export NOTE="# phantom PATH lookalike, not the marker"',
    ],
    sentinels: [
      'export PATH="/opt/other/bin:$PATH"',
      'alias ll="ls -la"',
      'export TRAILING_SPACES="kept"   ',
      'export NOTE="# phantom PATH lookalike, not the marker"',
    ],
  },
  zsh: {
    shell: '/bin/zsh',
    rc: (h) => join(h, '.zshrc'),
    line: (b) => `export PATH="${b}:$PATH"`,
    unrelated: [
      '# user shell config',
      'export EDITOR=vim',
      'export PATH="/opt/other/bin:$PATH"',
      '',
      '   ',
      'alias ll="ls -la"',
      'mkcd() {',
      '  mkdir -p "$1" && cd "$1"',
      '}',
      'if [ -f "$HOME/.localrc" ]; then',
      '  . "$HOME/.localrc"',
      'fi',
      'export TRAILING_SPACES="kept"   ',
      'export NOTE="# phantom PATH lookalike, not the marker"',
    ],
    sentinels: [
      'export PATH="/opt/other/bin:$PATH"',
      'alias ll="ls -la"',
      'export TRAILING_SPACES="kept"   ',
      'export NOTE="# phantom PATH lookalike, not the marker"',
    ],
  },
  fish: {
    shell: '/usr/bin/fish',
    rc: (h) => join(h, '.config', 'fish', 'config.fish'),
    line: (b) => `set -gx PATH "${b}" $PATH`,
    unrelated: [
      '# user shell config',
      'set -gx EDITOR vim',
      'set -gx PATH /opt/other/bin $PATH',
      '',
      '   ',
      'alias ll "ls -la"',
      'function mkcd',
      '    mkdir -p $argv[1]; and cd $argv[1]',
      'end',
      'if test -f ~/.localrc.fish',
      '    source ~/.localrc.fish',
      'end',
      'set -g TRAILING_SPACES "kept"   ',
      'set -g NOTE "# phantom PATH lookalike, not the marker"',
    ],
    sentinels: [
      'set -gx PATH /opt/other/bin $PATH',
      'alias ll "ls -la"',
      'set -g TRAILING_SPACES "kept"   ',
      'set -g NOTE "# phantom PATH lookalike, not the marker"',
    ],
  },
};

function runPathUpdate(harness, config, home, bin) {
  const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
    encoding: 'utf8',
    timeout: 30000,
    env: { HOME: home, SHELL: config.shell, PATH: '/usr/bin:/bin' },
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  return result;
}

for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  for (const [shellName, config] of Object.entries(shells)) {
    for (const finalNewline of [true, false]) {
      test(`${file} keeps every unrelated ${shellName} line unchanged (${finalNewline ? 'with' : 'without'} final newline)`, (t) => {
        const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-unrelated-')));
        t.after(() => rmSync(root, { recursive: true, force: true }));
        const home = join(root, 'home');
        const bin = join(root, 'live', 'bin');
        const rc = config.rc(home);
        mkdirSync(dirname(rc), { recursive: true });
        mkdirSync(bin, { recursive: true });
        const original = config.unrelated.join('\n') + (finalNewline ? '\n' : '');
        writeFileSync(rc, original, { mode: 0o600 });

        const result = runPathUpdate(harness, config, home, bin);
        assert.match(result.stdout, /added .* to PATH/);

        const originalLines = original.split('\n');
        const updatedLines = readFileSync(rc, 'utf8').split('\n');
        assert.deepEqual(updatedLines.slice(0, originalLines.length), originalLines,
          'every unrelated line is unchanged at its original index');
        assert.equal(updatedLines.length, originalLines.length + 3,
          'the update adds exactly the managed block');
        assert.deepEqual(updatedLines.slice(originalLines.length),
          [marker, config.line(bin), ''],
          'the appended tail is exactly the marker, the PATH line, and the final newline');
        for (const line of config.sentinels) {
          assert.equal(updatedLines.filter((l) => l === line).length, 1,
            `unrelated line ${JSON.stringify(line)} appears exactly once`);
        }
        assert.equal(statSync(rc).mode & 0o777, 0o600,
          'the startup file keeps its permissions');
        assert.deepEqual(
          readdirSync(dirname(rc)).filter((name) => name.startsWith('.phantom-path.')),
          [],
          'no PATH-update temporary files are left behind',
        );
      });
    }
  }

  test(`${file} leaves unrelated bash settings working after the update`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-unrelated-eval-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const home = join(root, 'home');
    const bin = join(root, 'live', 'bin');
    const rc = shells.bash.rc(home);
    mkdirSync(home, { recursive: true });
    mkdirSync(bin, { recursive: true });
    writeFileSync(rc, shells.bash.unrelated.join('\n') + '\n', { mode: 0o600 });

    const result = runPathUpdate(harness, shells.bash, home, bin);
    assert.match(result.stdout, /added .* to PATH/);

    // Source the updated startup file in a clean bash: the unrelated export,
    // alias, function, and if-block must still evaluate, and both PATH entries
    // must be live with the installer bin dir first.
    const check = spawnSync('/bin/bash', [
      '--noprofile', '--norc', '-c',
      'shopt -s expand_aliases; . "$HOME/.bashrc" && '
      + '[[ "$EDITOR" == vim ]] && alias ll >/dev/null && declare -F mkcd >/dev/null && '
      + '[[ "$PATH" == "$1:"* ]] && [[ "$PATH" == *"/opt/other/bin:"* ]]',
      'path-test', bin,
    ], {
      encoding: 'utf8',
      timeout: 30000,
      env: { HOME: home, PATH: '/usr/bin:/bin' },
    });
    assert.ifError(check.error);
    assert.equal(check.status, 0, check.stderr);
  });
}
