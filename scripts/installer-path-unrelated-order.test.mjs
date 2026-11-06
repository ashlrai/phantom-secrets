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

// The PATH update must keep the relative order of every unrelated line in the
// startup file. These fixtures make order detectable rather than incidental:
// SHARED is assigned twice (last assignment wins), two unrelated PATH prepends
// give aaa-later precedence only because its line comes second, ZEBRA precedes
// ALPHA so any sort visibly reorders them, and a comment documents the next
// line so a swap would detach them. The shipped add_to_user_path is extracted
// and run as in the sibling PATH tests, each original line is located by a
// forward scan, and a bash leg proves the sourced state is identical before
// and after the update — order preserved is order observed.
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

// Forward scan: each expected line must appear at or after the position after
// the previous match, so a missing or reordered line fails here. Exact
// equality means 'export A=1' never satisfies 'export A=12'.
function orderedIndexes(lines, expected) {
  const indexes = [];
  let cursor = 0;
  for (const line of expected) {
    const index = lines.indexOf(line, cursor);
    assert.ok(index >= cursor, `line missing or out of order: ${JSON.stringify(line)}`);
    indexes.push(index);
    cursor = index + 1;
  }
  return indexes;
}

const marker = '# phantom-secrets PATH';
const shells = {
  bash: {
    shell: '/bin/bash',
    rc: (h) => join(h, '.bashrc'),
    line: (b) => `export PATH="${b}:$PATH"`,
    unrelated: [
      '# section: tools',
      'export EDITOR=vim',
      'export ZEBRA=stripes',
      'export ALPHA=first-letter',
      'export SHARED=seed',
      '# the next line enables the widget',
      'export WIDGET=on',
      'alias ll="ls -la"',
      'jump() {',
      '  cd "$1"',
      '}',
      'export PATH="/opt/zzz-earlier/bin:$PATH"',
      'export PATH="/opt/aaa-later/bin:$PATH"',
      'export SHARED=final',
    ],
  },
  zsh: {
    shell: '/bin/zsh',
    rc: (h) => join(h, '.zshrc'),
    line: (b) => `export PATH="${b}:$PATH"`,
    unrelated: [
      '# section: tools',
      'export EDITOR=vim',
      'export ZEBRA=stripes',
      'export ALPHA=first-letter',
      'export SHARED=seed',
      '# the next line enables the widget',
      'export WIDGET=on',
      'alias ll="ls -la"',
      'jump() {',
      '  cd "$1"',
      '}',
      'export PATH="/opt/zzz-earlier/bin:$PATH"',
      'export PATH="/opt/aaa-later/bin:$PATH"',
      'export SHARED=final',
    ],
  },
  fish: {
    shell: '/usr/bin/fish',
    rc: (h) => join(h, '.config', 'fish', 'config.fish'),
    line: (b) => `set -gx PATH "${b}" $PATH`,
    unrelated: [
      '# section: tools',
      'set -gx EDITOR vim',
      'set -gx ZEBRA stripes',
      'set -gx ALPHA first-letter',
      'set -gx SHARED seed',
      '# the next line enables the widget',
      'set -gx WIDGET on',
      'alias ll "ls -la"',
      'function jump',
      '    cd $argv[1]',
      'end',
      'set -gx PATH /opt/zzz-earlier/bin $PATH',
      'set -gx PATH /opt/aaa-later/bin $PATH',
      'set -gx SHARED final',
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
    test(`${file} preserves a comment between unrelated ${shellName} assignments`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-comment-order-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'bin');
      const rc = config.rc(home);
      mkdirSync(dirname(rc), { recursive: true });
      mkdirSync(bin, { recursive: true });
      const assignments = shellName === 'fish'
        ? ['set -gx EDITOR vim', '# keep this comment between assignments', 'set -gx PAGER less']
        : ['export EDITOR=vim', '# keep this comment between assignments', 'export PAGER=less'];
      const original = `${assignments.join('\n')}\n`;
      writeFileSync(rc, original, { mode: 0o600 });

      runPathUpdate(harness, config, home, bin);

      assert.equal(readFileSync(rc, 'utf8'),
        `${original}\n${marker}\n${config.line(bin)}\n`,
        'all three lines remain intact and in order before the PATH block');
    });
  }
  for (const [shellName, config] of Object.entries(shells)) {
    for (const finalNewline of [true, false]) {
      test(`${file} keeps unrelated ${shellName} lines in their original order (${finalNewline ? 'with' : 'without'} final newline)`, (t) => {
        const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-order-')));
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
        // Relative order: every original line is found scanning forward, so
        // their positions are strictly increasing — the exact acceptance.
        const indexes = orderedIndexes(updatedLines, originalLines);
        // And nothing interleaves them: the original lines still form one
        // contiguous run, so the managed block cannot land between them.
        assert.equal(indexes.at(-1) - indexes[0], originalLines.length - 1,
          'no added line may be interleaved among the unrelated lines');
        assert.equal(updatedLines.length, originalLines.length + 3,
          'the update adds exactly the managed block');
        assert.deepEqual(updatedLines.slice(originalLines.length),
          [marker, config.line(bin), ''],
          'the appended tail is exactly the marker, the PATH line, and the final newline');
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

  for (const [shellName, config] of Object.entries(shells)) {
    test(`${file} keeps CRLF unrelated ${shellName} lines in order and byte-exact`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-crlf-order-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      const rc = config.rc(home);
      mkdirSync(dirname(rc), { recursive: true });
      mkdirSync(bin, { recursive: true });
      const original = `${config.unrelated.join('\r\n')}\r\n`;
      writeFileSync(rc, original, { mode: 0o600 });

      runPathUpdate(harness, config, home, bin);

      assert.equal(readFileSync(rc, 'utf8'),
        `${original}\n${marker}\n${config.line(bin)}\n`,
        'CRLF lines keep their bytes and order; the block is appended after them');
    });

    test(`${file} leaves a wired ${shellName} file with unrelated lines on both sides byte-identical`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-wired-order-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      const rc = config.rc(home);
      mkdirSync(dirname(rc), { recursive: true });
      mkdirSync(bin, { recursive: true });
      const half = config.unrelated.length >> 1;
      const original = [
        ...config.unrelated.slice(0, half),
        marker,
        config.line(bin),
        ...config.unrelated.slice(half),
      ].join('\n') + '\n';
      writeFileSync(rc, original, { mode: 0o600 });

      const result = runPathUpdate(harness, config, home, bin);

      assert.match(result.stdout, /already wired/);
      assert.equal(readFileSync(rc, 'utf8'), original,
        'an already-wired file is not rewritten, so no line moves');
    });
  }

  test(`${file} keeps the same shell state when bash sources the file before and after`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-order-eval-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const home = join(root, 'home');
    const bin = join(root, 'live', 'bin');
    const rc = shells.bash.rc(home);
    mkdirSync(home, { recursive: true });
    mkdirSync(bin, { recursive: true });
    writeFileSync(rc, shells.bash.unrelated.join('\n') + '\n', { mode: 0o600 });

    // Before the update the last SHARED assignment wins and the later PATH
    // prepend outranks the earlier one; the managed block is not present yet.
    const probe = (extra) => {
      const check = spawnSync('/bin/bash', [
        '--noprofile', '--norc', '-c',
        'shopt -s expand_aliases; . "$1" && '
        + '[[ "$SHARED" == final ]] && [[ "$WIDGET" == on ]] '
        + '&& alias ll >/dev/null && declare -F jump >/dev/null && ' + extra,
        'path-test', rc,
      ], {
        encoding: 'utf8',
        timeout: 30000,
        env: { HOME: home, PATH: '/usr/bin:/bin' },
      });
      assert.ifError(check.error);
      return check;
    };
    const before = probe('[[ "$PATH" == "/opt/aaa-later/bin:/opt/zzz-earlier/bin:/usr/bin:/bin" ]]');
    assert.equal(before.status, 0, before.stderr);

    const result = runPathUpdate(harness, shells.bash, home, bin);
    assert.match(result.stdout, /added .* to PATH/);

    // After the update the install dir is prepended but the relative order of
    // the two unrelated PATH entries — and every other observed value — is
    // exactly what sourcing the original file produced.
    const after = probe(`[[ "$PATH" == "${bin}:/opt/aaa-later/bin:/opt/zzz-earlier/bin:/usr/bin:/bin" ]]`);
    assert.equal(after.status, 0, after.stderr);
  });
}

test('the order assertion rejects reordered or dropped lines', () => {
  assert.throws(
    () => orderedIndexes(['a', 'b', 'c'], ['a', 'c', 'b']),
    /missing or out of order/,
  );
  assert.throws(
    () => orderedIndexes(['a', 'b', 'c'], ['a', 'x']),
    /missing or out of order/,
  );
  assert.throws(
    () => orderedIndexes(['export A=1', 'export A=12', 'export A=1'], ['export A=1', 'export A=1', 'export A=12']),
    /missing or out of order/,
  );
});
