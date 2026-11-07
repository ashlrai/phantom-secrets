import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import test from 'node:test';
import { pathUpdateHarness } from './lib/installer-path-harness.mjs';
import {
  assertMode600,
  assertNoPathTempFiles,
  assertOriginalPrefixThenBlock,
  createStartupFixture,
  marker,
  pathShellConfigs,
} from './lib/installer-path-test-fixtures.mjs';

// An isolated shell configuration keeps every comment byte-for-byte through
// the PATH update. Compared as raw Buffers, not decoded text: a file whose
// lines are all comments — shebang-style, bare #, indented, no-space,
// punctuation-heavy, non-UTF-8 — may only gain the managed marker block after
// its original bytes. Comments that nearly contain the marker still get the
// block appended; a repeat update never moves a byte.
//
// Policy note (retention of the original comments suite): the original
// expected comments that embed "# phantom-secrets PATH" as a substring to
// short-circuit as "already wired". The shipped probe is now `grep -qxF` —
// only a whole line exactly equal to the marker counts as wired — so those
// same comments correctly take the append path, exactly as
// installer-path-unrelated-comment.test.mjs documents for its embedded
// near-matches and installer-path-unrelated-final-line.test.mjs covers with
// its doubled-hash marker line. The embedded vectors below are retained with
// the current-policy expectation: appended once, every byte preserved.
const copies = {
  'scripts/install.sh': resolve(import.meta.dirname, 'install.sh'),
  'apps/web/public/install.sh': resolve(import.meta.dirname, '..', 'apps', 'web', 'public', 'install.sh'),
};

const shells = pathShellConfigs({});

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

// Each of these embeds the marker as a substring but none is a whole-line
// marker, so under the exact-line `grep -qxF` probe the update appends its
// block and every comment stays put.
const embedded = Buffer.from([
  '# note from an earlier install attempt',
  '## phantom-secrets PATH',
  '# phantom-secrets PATH: kept by hand',
  '# phantom-secrets PATHS',
  '# see # phantom-secrets PATH above',
].join('\n') + '\n');

// The original bytes must stay an exact prefix, the only addition must be the
// managed block, the mode must be kept, and no temporary files may remain.
function assertCleanUpdate(config, rc, original, bin) {
  const updated = assertOriginalPrefixThenBlock(rc, original, config, bin, {
    prefix: 'every pre-existing byte, comments included, is unchanged',
    appended: 'only the managed block is appended',
  });
  assertMode600(rc);
  assertNoPathTempFiles(rc);
  return updated;
}

for (const [file, installer] of Object.entries(copies)) {
  const harness = pathUpdateHarness(readFileSync(installer, 'utf8'), file);
  for (const [shellName, config] of Object.entries(shells)) {
    for (const trailing of ['\n', '']) {
      test(`${file} keeps an all-comment ${shellName} file byte-for-byte (${trailing ? 'with' : 'without'} final newline)`, (t) => {
        const original = Buffer.concat([commentOnly, Buffer.from(trailing)]);
        const { rc, bin, run } = createStartupFixture(t, {
          prefix: `phantom-path-comments-${shellName}-`, harness, config, content: original,
        });

        const first = run();
        assert.match(first.stdout, /added .* to PATH/);
        const updated = assertCleanUpdate(config, rc, original, bin);
        for (const line of original.toString('latin1').split('\n').filter((l) => l.startsWith('#') || l.match(/^\s+#/))) {
          assert.equal(updated.toString('latin1').indexOf(line),
            original.toString('latin1').indexOf(line),
            `comment ${JSON.stringify(line)} stays at its offset`);
        }

        const second = run();
        assert.match(second.stdout, /already wired into/);
        assert.ok(readFileSync(rc).equals(updated), 'a repeat update changes nothing');
      });
    }

    test(`${file} appends after marker-lookalike comments in a ${shellName} file`, (t) => {
      const original = Buffer.from(lookalikes.join('\n') + '\n');
      const { rc, bin, run } = createStartupFixture(t, {
        prefix: `phantom-path-comments-${shellName}-lookalike-`, harness, config, content: original,
      });

      const result = run();
      assert.match(result.stdout, /added .* to PATH/);
      const updated = assertCleanUpdate(config, rc, original, bin);
      for (const line of lookalikes) {
        assert.equal(updated.toString('utf8').split('\n').filter((l) => l === line).length, 1,
          `lookalike comment ${JSON.stringify(line)} appears exactly once`);
      }
    });

    test(`${file} appends one managed block after ${shellName} comments embedding the marker`, (t) => {
      const { rc, bin, run } = createStartupFixture(t, {
        prefix: `phantom-path-comments-${shellName}-embedded-`, harness, config, content: embedded,
      });

      const result = run();
      assert.match(result.stdout, /added .* to PATH/);
      const updated = assertCleanUpdate(config, rc, embedded, bin);
      const updatedLines = updated.toString('utf8').split('\n');
      assert.equal(updatedLines.filter((l) => l === marker).length, 1,
        'exactly one real marker line after the update');
      for (const line of embedded.toString('utf8').split('\n').filter(Boolean)) {
        assert.equal(updatedLines.filter((l) => l === line).length, 1,
          `embedded comment ${JSON.stringify(line)} appears exactly once`);
      }

      const second = run();
      assert.match(second.stdout, /already wired into/);
      assert.ok(readFileSync(rc).equals(updated), 'a repeat update changes nothing');
    });
  }
}
