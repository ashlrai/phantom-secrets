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
  managedBlock,
  marker,
  pathShellConfigs,
} from './lib/installer-path-test-fixtures.mjs';

// Preserve unrelated comments and append only for marker near-matches.
const copies = {
  'scripts/install.sh': resolve(process.cwd(), 'scripts/install.sh'),
  'apps/web/public/install.sh': resolve(process.cwd(), 'apps/web/public/install.sh'),
};

const posixSettings = { setting: 'export EDITOR=vim', alias: 'alias ll="ls -la"' };
const shells = pathShellConfigs({
  bash: posixSettings,
  zsh: posixSettings,
  fish: { setting: 'set -gx EDITOR vim', alias: 'alias ll "ls -la"' },
});

// Unrelated comments that mention Phantom or PATH without containing the exact
// marker text. None is the managed block, so the update must still run and
// must leave each comment alone.
const unrelatedComments = [
  '# my shell customizations',
  '#phantom-secrets PATH', // no space after '#'
  '# phantom-secrets  PATH', // two spaces before PATH
  '# Phantom-secrets PATH', // the marker words in another case
  '# notes about phantom-secrets PATH handling', // marker words without '# ' adjacency
  '# the PATH entry moved into ~/.zprofile',
];

const layouts = [
  ['comments above a setting', (c) => [unrelatedComments[0], unrelatedComments[1], c.setting]],
  ['comments between settings', (c) => [c.setting, unrelatedComments[2], unrelatedComments[3], c.alias]],
  ['a comment as the last line', (c) => [c.setting, unrelatedComments[4]]],
  ['a file of comments only', () => [...unrelatedComments]],
];

// Comments that contain the marker as a substring. The documented
// exact-line policy appends a standalone managed block for these near-matches.
const embeddedMarkerComments = [
  '# phantom-secrets PATH was wired by hand here',
  '# note: # phantom-secrets PATH lives elsewhere',
];

for (const [file, installer] of Object.entries(copies)) {
  const harness = pathUpdateHarness(readFileSync(installer, 'utf8'), file);
  for (const [shellName, config] of Object.entries(shells)) {
    for (const [layout, build] of layouts) {
      for (const finalNewline of [true, false]) {
        test(`${file} keeps unrelated ${shellName} comments unchanged (${layout}, ${finalNewline ? 'with' : 'without'} final newline)`, (t) => {
          const lines = build(config);
          const original = Buffer.from(lines.join('\n') + (finalNewline ? '\n' : ''), 'utf8');
          const { rc, bin, run } = createStartupFixture(t, {
            prefix: 'phantom-path-comment-', harness, config, content: original,
          });

          const first = run();
          assert.match(first.stdout, /added .* to PATH/);

          const updated = assertOriginalPrefixThenBlock(rc, original, config, bin, {
            prefix: 'every pre-existing byte, including each unrelated comment, is unchanged',
            appended: 'only the managed marker block is appended',
          });
          for (const comment of lines.filter((l) => l.startsWith('#'))) {
            assert.equal(updated.indexOf(comment), original.indexOf(comment),
              `comment ${JSON.stringify(comment)} stays at the same offset`);
          }
          assert.equal(updated.toString('utf8').split(marker).length - 1, 1,
            'the only marker text in the file is the appended managed one');
          assertMode600(rc);
          assertNoPathTempFiles(rc);

          const second = run();
          assert.match(second.stdout, /already wired into/);
          assert.ok(readFileSync(rc).equals(updated),
            'a repeat update changes nothing, comments included');
        });
      }
    }

    for (const comment of embeddedMarkerComments) {
      test(`${file} appends after a ${shellName} comment embedding the marker`, (t) => {
        const original = Buffer.from(`${config.setting}\n${comment}\n`, 'utf8');
        const { rc, bin, run } = createStartupFixture(t, {
          prefix: 'phantom-path-embedded-', harness, config, content: original,
        });

        const result = run();
        assert.match(result.stdout, /added .* to PATH/);
        assert.ok(readFileSync(rc).equals(Buffer.concat([original, Buffer.from(managedBlock(config, bin))])),
          'embedded marker is preserved and a standalone marker block is appended');
        assertNoPathTempFiles(rc, 'the update leaves no PATH-update temporary files');
      });
    }
  }
}
