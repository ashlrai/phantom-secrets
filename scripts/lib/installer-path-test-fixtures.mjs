import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { createPathUpdateFixture, installerPathShellCases } from './installer-path-harness.mjs';

// TEST-only helpers shared by the installer PATH-preservation suites. They own
// the repeated startup-file setup and the repeated "original bytes kept, only
// the managed block appended" assertions; each suite keeps its own fixture
// lines, case names and per-case expectations.

export const marker = '# phantom-secrets PATH';

// The three supported shells with their startup file, managed PATH line, and the
// suite's own per-shell fixture data (`extra.<shell>`) merged in.
export function pathShellConfigs(extra) {
  const cases = installerPathShellCases();
  return Object.fromEntries(Object.entries(cases).map(([name, { shell, rc, pathLine }]) => [
    name, { shell, rc, line: pathLine, ...extra[name] },
  ]));
}

// Exact bytes the update appends to a file that was not yet wired.
export const managedBlock = (config, bin) => `\n${marker}\n${config.line(bin)}\n`;

// Fixture owning a temp HOME/bin plus the shipped harness runner. `content`
// (a string, Buffer, or a function of the fixture) is written as the 0600
// startup file before the caller runs the update.
export function createStartupFixture(t, { prefix, harness, config, content }) {
  const fixture = createPathUpdateFixture(t, { prefix, harness, config });
  if (content !== undefined) {
    const bytes = typeof content === 'function' ? content(fixture) : content;
    writeFileSync(fixture.rc, bytes, { mode: 0o600 });
  }
  return fixture;
}

export function assertNoPathTempFiles(rc, message = 'no PATH-update temporary files are left behind') {
  assert.deepEqual(
    readdirSync(dirname(rc)).filter((name) => name.startsWith('.phantom-path.')),
    [],
    message,
  );
}

export function assertMode600(rc) {
  assert.equal(statSync(rc).mode & 0o777, 0o600, 'the startup file keeps its permissions');
}

// The original bytes must stay an exact prefix and the only addition must be the
// managed block. Returns the updated bytes for the caller's remaining checks.
export function assertOriginalPrefixThenBlock(rc, original, config, bin, messages) {
  const updated = readFileSync(rc);
  assert.ok(updated.subarray(0, original.length).equals(original), messages.prefix);
  assert.equal(updated.subarray(original.length).toString('utf8'),
    managedBlock(config, bin), messages.appended);
  return updated;
}

// Forward scan: each expected line must appear at or after the position after
// the previous match, so a missing or reordered line fails here. Exact
// equality means 'export A=1' never satisfies 'export A=12'.
export function orderedIndexes(lines, expected) {
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

// Order-sensitive unrelated lines: ZEBRA precedes ALPHA so a sort visibly
// reorders them, SHARED is assigned twice, a comment documents the next line,
// and two PATH prepends give aaa-later precedence only through position.
const posixUnrelated = [
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
];
const fishUnrelated = [
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
];

// Per-shell `unrelated` lines for pathShellConfigs, as copies so no suite can
// mutate another suite's fixture.
export function unrelatedOrderLines() {
  return {
    bash: { unrelated: [...posixUnrelated] },
    zsh: { unrelated: [...posixUnrelated] },
    fish: { unrelated: [...fishUnrelated] },
  };
}

// After an update of `original` (a string): every original line is present in
// strict forward order as one contiguous run, followed by exactly the managed
// block, with the file mode kept and no temporary files left.
export function assertUnrelatedOrderKept(rc, original, config, bin) {
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
  assertMode600(rc);
  assertNoPathTempFiles(rc);
}
