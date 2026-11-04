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

// An isolated shell configuration keeps every comment byte-for-byte through
// the PATH update. Compared as raw Buffers, not decoded text: a file whose
// lines are all comments — shebang-style, bare #, indented, no-space,
// punctuation-heavy, non-UTF-8 — may only gain the managed marker block after
// its original bytes. Comments that nearly contain the marker still get the
// block appended; comments that literally embed "# phantom-secrets PATH" make
// the fixed-string probe report "already wired" before any rewrite, so the
// whole file stays untouched. A repeat update never moves a byte.
const copies = {
  'scripts/install.sh': resolve(import.meta.dirname, 'install.sh'),
  'apps/web/public/install.sh': resolve(import.meta.dirname, '..', 'apps', 'web', 'public', 'install.sh'),
};

function extractFunction(source, name, file) {
  const start = source.indexOf(`${name}()`);
  assert.ok(start >= 0, `${file}: locate ${name}`);
  const lineEnd = source.indexOf('\n', start);
  if (source.slice(start, lineEnd).trimEnd().endsWith('}')) return source.slice(start, lineEnd + 1);
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
    shell: '/bin/bash', rc: (h) => join(h, '.bashrc'),
    line: (b) => `export PATH="${b}:$PATH"`,
  },
  zsh: {
    shell: '/bin/zsh', rc: (h) => join(h, '.zshrc'),
    line: (b) => `export PATH="${b}:$PATH"`,
  },
  fish: {
    shell: '/usr/bin/fish', rc: (h) => join(h, '.config', 'fish', 'config.fish'),
    line: (b) => `set -gx PATH "${b}" $PATH`,
  },
};

// Every line is a comment; the last one has no newline of its own.
const commentOnly = Buffer.concat([
  Buffer.from('#!/usr/bin/env bash\n'),
  Buffer.from('#\n'),
  Buffer.from('# header comment\n# second header line\n'),
  Buffer.from('   # indented, with trailing spaces   \n'),
  Buffer.from('\t# tab-indented\n'),
  Buffer.from('#no space after the hash\n'),
  Buffer.from('# `backticks` $(subshell) ${VAR} $HOME * ? [a-z] &|;!\n'),
  Buffer.from('# café 日本語 🚀\n'),
  Buffer.from('# legacy latin-1: caf'),
  Buffer.from([0xe9, 0x0a]),
  Buffer.from('# final comment'),
]);

// None of these contain the marker as a fixed substring, so the update must
// still append its block and leave each comment in place.
const lookalikes = [
  '#phantom-secrets PATH',
  '#  phantom-secrets PATH',
  '# phantom-secrets  PATH',
  '# Phantom-secrets PATH',
  '# phantom-secrets path',
  '# phantom-secrets PAT',
  '# a phantom-secrets PATH note',
];

// Each of these embeds the marker, so the probe short-circuits to "already
// wired" and the file is never rewritten.
const embedded = Buffer.from([
  '# note from an earlier install attempt',
  '## phantom-secrets PATH',
  '# phantom-secrets PATH: kept by hand',
  '# phantom-secrets PATHS',
  '# see # phantom-secrets PATH above',
].join('\n') + '\n');

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

function makeHome(t, config, tag) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), `phantom-path-comments-${tag}-`)));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const home = join(root, 'home');
  const bin = join(root, 'live', 'bin');
  const rc = config.rc(home);
  mkdirSync(dirname(rc), { recursive: true });
  mkdirSync(bin, { recursive: true });
  return { home, bin, rc };
}

function assertCleanUpdate(config, rc, original, bin) {
  const updated = readFileSync(rc);
  assert.ok(updated.subarray(0, original.length).equals(original),
    'every pre-existing byte, comments included, is unchanged');
  assert.equal(updated.subarray(original.length).toString('utf8'),
    `\n${marker}\n${config.line(bin)}\n`,
    'only the managed block is appended');
  assert.equal(statSync(rc).mode & 0o777, 0o600,
    'the startup file keeps its permissions');
  assert.deepEqual(
    readdirSync(dirname(rc)).filter((name) => name.startsWith('.phantom-path.')),
    [],
    'no PATH-update temporary files are left behind',
  );
  return updated;
}

for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  for (const [shellName, config] of Object.entries(shells)) {
    for (const trailing of ['\n', '']) {
      test(`${file} keeps an all-comment ${shellName} file byte-for-byte (${trailing ? 'with' : 'without'} final newline)`, (t) => {
        const { home, bin, rc } = makeHome(t, config, shellName);
        const original = Buffer.concat([commentOnly, Buffer.from(trailing)]);
        writeFileSync(rc, original, { mode: 0o600 });

        const first = runPathUpdate(harness, config, home, bin);
        assert.match(first.stdout, /added .* to PATH/);
        const updated = assertCleanUpdate(config, rc, original, bin);
        for (const line of original.toString('latin1').split('\n').filter((l) => l.startsWith('#') || l.match(/^\s+#/))) {
          assert.equal(updated.toString('latin1').indexOf(line),
            original.toString('latin1').indexOf(line),
            `comment ${JSON.stringify(line)} stays at its offset`);
        }

        const second = runPathUpdate(harness, config, home, bin);
        assert.match(second.stdout, /already wired into/);
        assert.ok(readFileSync(rc).equals(updated), 'a repeat update changes nothing');
      });
    }

    test(`${file} appends after marker-lookalike comments in a ${shellName} file`, (t) => {
      const { home, bin, rc } = makeHome(t, config, `${shellName}-lookalike`);
      const original = Buffer.from(lookalikes.join('\n') + '\n');
      writeFileSync(rc, original, { mode: 0o600 });

      const result = runPathUpdate(harness, config, home, bin);
      assert.match(result.stdout, /added .* to PATH/);
      const updated = assertCleanUpdate(config, rc, original, bin);
      for (const line of lookalikes) {
        assert.equal(updated.toString('utf8').split('\n').filter((l) => l === line).length, 1,
          `lookalike comment ${JSON.stringify(line)} appears exactly once`);
      }
    });

    test(`${file} leaves a ${shellName} file whose comments embed the marker untouched`, (t) => {
      const { home, bin, rc } = makeHome(t, config, `${shellName}-embedded`);
      writeFileSync(rc, embedded, { mode: 0o600 });

      const result = runPathUpdate(harness, config, home, bin);
      assert.match(result.stdout, /already wired into/);
      assert.ok(readFileSync(rc).equals(embedded),
        'the whole startup file, comments included, is byte-for-byte unchanged');
      assert.deepEqual(
        readdirSync(dirname(rc)).filter((name) => name.startsWith('.phantom-path.')),
        [],
        'no PATH-update temporary files are left behind',
      );
    });
  }
}
