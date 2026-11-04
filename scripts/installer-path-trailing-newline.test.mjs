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
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

// Companion to installer-path-final-newline.test.mjs, which covers startup
// files that lack a final newline. This file covers the ordinary case: a
// shell startup file that already ends in a newline. The shipped
// add_to_user_path is extracted verbatim — same as
// installer-path-idempotence.test.mjs — and driven against newline-terminated
// files. The function appends its PATH block through a candidate copy with a
// leading newline, so every original byte, the final terminator included,
// must survive as an untouched prefix with one blank separator line between
// the hand-written content and the managed marker block.
const installers = {
  'scripts/install.sh': new URL('install.sh', import.meta.url),
  'apps/web/public/install.sh': new URL('../apps/web/public/install.sh', import.meta.url),
};

const shells = {
  bash: {
    shell: '/bin/bash',
    rcPath: (home) => join(home, '.bashrc'),
    pathLine: (install) => `export PATH="${install}:$PATH"`,
  },
  zsh: {
    shell: '/bin/zsh',
    rcPath: (home) => join(home, '.zshrc'),
    pathLine: (install) => `export PATH="${install}:$PATH"`,
  },
  fish: {
    shell: '/usr/bin/fish',
    rcPath: (home) => join(home, '.config', 'fish', 'config.fish'),
    pathLine: (install) => `set -gx PATH "${install}" $PATH`,
  },
};

const marker = '# phantom-secrets PATH';

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

const pathUpdateHarness = (source, file) => ['set -euo pipefail', 'umask 077',
  ...['say', 'file_identity', 'file_link_count', 'add_to_user_path']
    .map((name) => extractFunction(source, name, file)),
  'add_to_user_path "$1"',
].join('\n');

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

// Newline-terminated shapes a startup file can take. In every case the
// pre-existing bytes, terminators included, must survive untouched.
const terminatedShapes = (shellName) => [
  ['a single terminated line', 'export EDITOR=vim\n'],
  ['a terminated trailing comment', '# user shell config\n# hand-written note\n'],
  ['extra trailing blank lines', 'export EDITOR=vim\n\n\n'],
  ['a terminated PATH entry of its own',
    `# user shell config\n${shellName === 'fish'
      ? 'set -gx PATH "/opt/tools/bin" $PATH'
      : 'export PATH="/opt/tools/bin:$PATH"'}\n`],
  ['nothing but a newline', '\n'],
];

function assertPreservedTerminatedFile(rc, bin, config, text) {
  const updated = readFileSync(rc, 'utf8');
  assert.ok(updated.startsWith(text),
    'the original content and its final newline are an untouched prefix');
  assert.equal(updated, `${text}\n${marker}\n${config.pathLine(bin)}\n`);
  const lines = updated.split('\n');
  const originalLines = text.split('\n');
  assert.deepEqual(lines.slice(0, originalLines.length), originalLines,
    'every original line keeps its index, terminator included');
  assert.equal(lines.filter((line) => line === marker).length, 1,
    'the marker is a separate line');
  assert.ok(lines.includes(config.pathLine(bin)),
    'the PATH line is a separate line');
  assert.equal(statSync(rc).mode & 0o777, 0o600,
    'startup file mode is preserved');
  assert.deepEqual(
    readdirSync(dirname(rc)).filter((name) => name.startsWith('.phantom-path.')),
    [],
    'no PATH-update temporary files remain beside the startup file',
  );
}

for (const [label, url] of Object.entries(installers)) {
  const harness = pathUpdateHarness(readFileSync(fileURLToPath(url), 'utf8'), label);
  for (const [shellName, config] of Object.entries(shells)) {
    for (const [shape, text] of terminatedShapes(shellName)) {
      test(`${label} appends after the terminator in a ${shellName} file with ${shape}`, (t) => {
        const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-trailing-shape-')));
        t.after(() => rmSync(root, { recursive: true, force: true }));
        const home = join(root, 'home');
        const bin = join(root, 'live', 'bin');
        const rc = config.rcPath(home);
        mkdirSync(dirname(rc), { recursive: true });
        mkdirSync(bin, { recursive: true });
        writeFileSync(rc, text, { mode: 0o600 });

        const result = runPathUpdate(harness, config, home, bin);
        assert.match(result.stdout, /added .* to PATH/);
        assertPreservedTerminatedFile(rc, bin, config, text);
      });
    }

    test(`${label} leaves a wired newline-terminated ${shellName} file untouched`, (t) => {
      // A file the installer already recognizes — the marker is present and
      // the file ends in a newline — comes back byte-for-byte identical:
      // the update neither appends nor rewrites a wired file, so every byte,
      // terminator included, survives.
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-trailing-wired-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      const rc = config.rcPath(home);
      mkdirSync(dirname(rc), { recursive: true });
      mkdirSync(bin, { recursive: true });
      const text = `# user shell config\nexport EDITOR=vim\n\n${marker}\n${config.pathLine(bin)}\n`;
      writeFileSync(rc, text, { mode: 0o600 });

      const result = runPathUpdate(harness, config, home, bin);
      assert.match(result.stdout, /already wired into/);
      assert.doesNotMatch(result.stdout, /added .* to PATH/);
      assert.equal(readFileSync(rc, 'utf8'), text,
        'the recognized startup file is byte-for-byte unchanged');
      assert.equal(statSync(rc).mode & 0o777, 0o600,
        'startup file mode is preserved');
      assert.deepEqual(
        readdirSync(dirname(rc)).filter((name) => name.startsWith('.phantom-path.')),
        [],
        'no PATH-update temporary files remain beside the startup file',
      );
    });

    test(`${label} adds nothing on a second ${shellName} update after a terminated file`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-trailing-repeat-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      const rc = config.rcPath(home);
      mkdirSync(dirname(rc), { recursive: true });
      mkdirSync(bin, { recursive: true });
      const text = '# user shell config\nexport EDITOR=vim\n';
      writeFileSync(rc, text, { mode: 0o600 });

      const first = runPathUpdate(harness, config, home, bin);
      assert.match(first.stdout, /added .* to PATH/);
      assertPreservedTerminatedFile(rc, bin, config, text);
      const wired = readFileSync(rc, 'utf8');

      const second = runPathUpdate(harness, config, home, bin);
      assert.match(second.stdout, /already wired into/);
      assert.doesNotMatch(second.stdout, /added .* to PATH/,
        'the second update must not append a second PATH block');
      assert.equal(readFileSync(rc, 'utf8'), wired,
        'the second update leaves the startup file byte-for-byte unchanged');
      assert.deepEqual(
        readdirSync(dirname(rc)).filter((name) => name.startsWith('.phantom-path.')),
        [],
        'no PATH-update temporary files remain beside the startup file',
      );
    });

    test(`${label} appends past a terminated ${shellName} file mentioning the marker`, (t) => {
      // grep -qxF matches only a whole-line marker, so an unrelated line that
      // merely quotes the marker text is not a managed block: the update
      // appends while the newline-terminated file is preserved byte-for-byte,
      // and a repeat update then short-circuits on the real marker line.
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-trailing-mention-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      const rc = config.rcPath(home);
      mkdirSync(dirname(rc), { recursive: true });
      mkdirSync(bin, { recursive: true });
      const text = `# user shell config\n# review note: keep the ${marker} line\n`;
      writeFileSync(rc, text, { mode: 0o600 });

      const result = runPathUpdate(harness, config, home, bin);
      assert.match(result.stdout, /added .* to PATH/);
      assertPreservedTerminatedFile(rc, bin, config, text);

      const wired = readFileSync(rc, 'utf8');
      const second = runPathUpdate(harness, config, home, bin);
      assert.match(second.stdout, /already wired into/);
      assert.doesNotMatch(second.stdout, /added .* to PATH/,
        'the repeat update must not append a second PATH block');
      assert.equal(readFileSync(rc, 'utf8'), wired,
        'the repeat update leaves the file byte-for-byte unchanged');
    });
  }
}

// The UTF-8 reads above would hide a rewritten byte. A startup file may hold
// CRLF terminators or Latin-1 and other non-UTF-8 bytes; the original bytes —
// line endings included — must come back exactly, followed only by the
// separator and the managed block.
for (const [label, url] of Object.entries(installers)) {
  const harness = pathUpdateHarness(readFileSync(fileURLToPath(url), 'utf8'), label);
  for (const [shellName, config] of Object.entries(shells)) {
    for (const [shape, original] of [
      ['CRLF', Buffer.from('# user shell config\r\nexport EDITOR=vim\r\n')],
      ['non-UTF-8', Buffer.concat([
        Buffer.from('# caf'), Buffer.from([0xe9, 0xff, 0xfe]),
        Buffer.from('\nexport NAME=a\n'),
      ])],
    ]) {
      test(`${label} keeps ${shape} bytes in a newline-terminated ${shellName} file exactly`, (t) => {
        const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-trailing-bytes-')));
        t.after(() => rmSync(root, { recursive: true, force: true }));
        const home = join(root, 'home');
        const bin = join(root, 'live', 'bin');
        const rc = config.rcPath(home);
        mkdirSync(dirname(rc), { recursive: true });
        mkdirSync(bin, { recursive: true });
        writeFileSync(rc, original, { mode: 0o600 });

        const result = runPathUpdate(harness, config, home, bin);
        assert.match(result.stdout, /added .* to PATH/);
        const expected = Buffer.concat([
          original, Buffer.from(`\n${marker}\n${config.pathLine(bin)}\n`),
        ]);
        assert.ok(readFileSync(rc).equals(expected),
          'original bytes and terminators are preserved; only the block is appended');
      });
    }
  }
}
