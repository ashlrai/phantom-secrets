import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { pathUpdateHarness } from './lib/installer-path-harness.mjs';
import {
  assertMode600,
  assertNoPathTempFiles,
  assertUnrelatedOrderKept,
  createStartupFixture,
  managedBlock,
  marker,
  orderedIndexes,
  pathShellConfigs,
  unrelatedOrderLines,
} from './lib/installer-path-test-fixtures.mjs';

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

const unrelatedByShell = unrelatedOrderLines();
const laterPosix = [
  '# appended by a later tool',
  'export LATE_TOOL=on',
  'alias gs="git status"',
];
const shells = pathShellConfigs({
  bash: { ...unrelatedByShell.bash, later: laterPosix },
  zsh: { ...unrelatedByShell.zsh, later: [...laterPosix] },
  fish: {
    ...unrelatedByShell.fish,
    later: [
      '# appended by a later tool',
      'set -gx LATE_TOOL on',
      'alias gs "git status"',
    ],
  },
});

// One order case, shared by the canonical and reversed legs: write the
// unrelated lines exactly as given, run the update, then prove the updated
// file keeps every original line as one strictly ordered, contiguous run
// followed by exactly the managed block.
function runOrderCase(t, harness, config, unrelated, finalNewline) {
  const original = unrelated.join('\n') + (finalNewline ? '\n' : '');
  const { rc, bin, run } = createStartupFixture(t, {
    prefix: 'phantom-path-order-', harness, config, content: original,
  });

  const result = run();
  assert.match(result.stdout, /added .* to PATH/);

  assertUnrelatedOrderKept(rc, original, config, bin);
}

for (const [file, installer] of Object.entries(copies)) {
  const harness = pathUpdateHarness(readFileSync(installer, 'utf8'), file);
  for (const [shellName, config] of Object.entries(shells)) {
    test(`${file} preserves a comment between unrelated ${shellName} assignments`, (t) => {
      const assignments = shellName === 'fish'
        ? ['set -gx EDITOR vim', '# keep this comment between assignments', 'set -gx PAGER less']
        : ['export EDITOR=vim', '# keep this comment between assignments', 'export PAGER=less'];
      const original = `${assignments.join('\n')}\n`;
      const { rc, bin, run } = createStartupFixture(t, {
        prefix: 'phantom-path-comment-order-', harness, config, content: original,
      });

      run();

      assert.equal(readFileSync(rc, 'utf8'), `${original}${managedBlock(config, bin)}`,
        'all three lines remain intact and in order before the PATH block');
    });
  }
  for (const [shellName, config] of Object.entries(shells)) {
    for (const finalNewline of [true, false]) {
      // The acceptance property is the file's own order, not this fixture's:
      // the same unrelated lines written in reverse must come back in exactly
      // that reversed order, so the update cannot impose an order of its own.
      test(`${file} keeps unrelated ${shellName} lines in a reversed original order (${finalNewline ? 'with' : 'without'} final newline)`, (t) => {
        runOrderCase(t, harness, config, [...config.unrelated].reverse(), finalNewline);
      });
      test(`${file} keeps unrelated ${shellName} lines in their original order (${finalNewline ? 'with' : 'without'} final newline)`, (t) => {
        runOrderCase(t, harness, config, config.unrelated, finalNewline);
      });
    }
  }

  for (const [shellName, config] of Object.entries(shells)) {
    test(`${file} keeps unrelated ${shellName} lines below the managed block untouched on a repeat update`, (t) => {
      // A previous install wired its block; the user and other tools then
      // appended unrelated lines below it. The repeat update must see the
      // marker, report "already wired", and leave every line — before and
      // after the block — exactly where it was.
      let original;
      const { rc, run } = createStartupFixture(t, {
        prefix: 'phantom-path-after-block-', harness, config,
        content: ({ root }) => {
          const earlierBin = join(root, 'earlier', 'bin');
          original = `${config.unrelated.slice(0, 3).join('\n')}\n${marker}\n${config.line(earlierBin)}\n${config.later.join('\n')}\n`;
          return original;
        },
      });

      const result = run();
      assert.match(result.stdout, /already wired into/);
      assert.doesNotMatch(result.stdout, /added .* to PATH/);

      assert.equal(readFileSync(rc, 'utf8'), original,
        'unrelated lines on both sides of the managed block keep their bytes and order');
      assert.equal(original.split('\n').filter((line) => line === marker).length, 1,
        'the managed block stays a single block');
      assertMode600(rc);
      assertNoPathTempFiles(rc);
    });
    test(`${file} keeps CRLF unrelated ${shellName} lines in order and byte-exact`, (t) => {
      const original = `${config.unrelated.join('\r\n')}\r\n`;
      const { rc, bin, run } = createStartupFixture(t, {
        prefix: 'phantom-path-crlf-order-', harness, config, content: original,
      });

      run();

      assert.equal(readFileSync(rc, 'utf8'), `${original}${managedBlock(config, bin)}`,
        'CRLF lines keep their bytes and order; the block is appended after them');
    });

    test(`${file} leaves a wired ${shellName} file with unrelated lines on both sides byte-identical`, (t) => {
      let original;
      const { rc, run } = createStartupFixture(t, {
        prefix: 'phantom-path-wired-order-', harness, config,
        content: ({ bin }) => {
          const half = config.unrelated.length >> 1;
          original = [
            ...config.unrelated.slice(0, half),
            marker,
            config.line(bin),
            ...config.unrelated.slice(half),
          ].join('\n') + '\n';
          return original;
        },
      });

      const result = run();

      assert.match(result.stdout, /already wired/);
      assert.equal(readFileSync(rc, 'utf8'), original,
        'an already-wired file is not rewritten, so no line moves');
    });
  }

  test(`${file} keeps the same shell state when bash sources the file before and after`, (t) => {
    const { home, rc, bin, run } = createStartupFixture(t, {
      prefix: 'phantom-path-order-eval-', harness, config: shells.bash,
      content: shells.bash.unrelated.join('\n') + '\n',
    });

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

    const result = run();
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
