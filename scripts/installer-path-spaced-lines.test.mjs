import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import test from 'node:test';
import { pathUpdateHarness } from './lib/installer-path-harness.mjs';
import {
  assertOriginalPrefixThenBlock,
  createStartupFixture,
  marker,
  pathShellConfigs,
} from './lib/installer-path-test-fixtures.mjs';

// Unrelated startup-file lines that contain spaces — leading and trailing runs,
// runs of several spaces inside quotes, a tab/space mix, a path with spaces,
// and a space-only line — must survive the PATH update byte-for-byte, compared
// as raw Buffers. The original bytes stay an exact prefix, the only addition is
// the managed block, and a second update (or an already-wired file) changes
// nothing. Runs the shipped add_to_user_path from both installer copies.
const copies = {
  'scripts/install.sh': resolve(import.meta.dirname, 'install.sh'),
  'apps/web/public/install.sh': resolve(import.meta.dirname, '..', 'apps', 'web', 'public', 'install.sh'),
};

const originalSpaced = [
  '   leading spaces kept',
  'trailing spaces kept   ',
  'two  inner   gaps  here',
  '  # indented comment with  spaces  ',
  'alias gs="git status  --short"',
  'export MY_DIR="/Users/Jane Doe/My Tools/bin"',
  'cd "$HOME/Library/Application Support"',
  ' ',
  '    ',
];

// Each shell carries the current fixture (`spaced`) and the original-PR fixture
// (`originalLines`: the shared spaced lines plus that shell's own PATH line).
const shells = pathShellConfigs({
  bash: {
    spaced: [
      '   export LEADING="three spaces before"',
      'export INNER="a    b     c"',
      'export TRAILING="x"      ',
      '\t \texport MIXED="tab and space"',
      'export SPACED_PATH="/Users/Some One/My Tools/bin"',
      '      ',
      'alias   ll="ls   -la"',
      '  # indented   comment  with   gaps  ',
    ],
    originalLines: [...originalSpaced, 'export PATH="/Users/Jane Doe/My Tools/bin:$PATH"'],
  },
  zsh: {
    spaced: [
      '   export LEADING="three spaces before"',
      'export INNER="a    b     c"',
      'export TRAILING="x"      ',
      'setopt   no_beep   ',
      'export SPACED_PATH="/Users/Some One/My Tools/bin"',
      '      ',
      'alias   ll="ls   -la"',
      '  # indented   comment  with   gaps  ',
    ],
    originalLines: [...originalSpaced, 'export PATH="/Users/Jane Doe/My Tools/bin:$PATH"'],
  },
  fish: {
    spaced: [
      '   set -gx LEADING "three spaces before"',
      'set -gx INNER "a    b     c"',
      'set -gx TRAILING x      ',
      'set -gx SPACED_PATH "/Users/Some One/My Tools/bin"',
      '      ',
      'alias   ll "ls   -la"',
      '  # indented   comment  with   gaps  ',
    ],
    originalLines: [...originalSpaced, 'set -gx PATH "/Users/Jane Doe/My Tools/bin" $PATH'],
  },
});

for (const [file, installer] of Object.entries(copies)) {
  const harness = pathUpdateHarness(readFileSync(installer, 'utf8'), file);
  for (const [shellName, config] of Object.entries(shells)) {
    const setup = (t, content) => createStartupFixture(t, {
      prefix: `phantom-path-spaced-${shellName}-`, harness, config, content,
    });

    for (const [fixtureName, fixture] of [['current', config.spaced], ['original', config.originalLines]]) {
    for (const trailing of ['\n', '']) {
      test(`${file} keeps unrelated ${shellName} lines with spaces byte-for-byte (${fixtureName}, ${trailing ? 'with' : 'without'} final newline)`, (t) => {
        const original = Buffer.from(fixture.join('\n') + trailing);
        const { rc, bin, run } = setup(t, original);

        assert.match(run().stdout, /added .* to PATH/);
        const updated = assertOriginalPrefixThenBlock(rc, original, config, bin, {
          prefix: 'original bytes are an exact prefix of the updated file',
          appended: 'only the managed block is appended',
        });

        run();
        assert.ok(readFileSync(rc).equals(updated), 'a second update changes nothing');
      });
    }

    }

    test(`${file} keeps unrelated ${shellName} lines with spaces byte-for-byte when the PATH entry is already wired`, (t) => {
      let original;
      const { rc, run } = setup(t, ({ bin }) => {
        original = Buffer.from(`${config.spaced.join('\n')}\n${marker}\n${config.line(bin)}\n`);
        return original;
      });

      assert.match(run().stdout, /already wired into/);
      assert.ok(readFileSync(rc).equals(original), 'the whole startup file is byte-for-byte unchanged');
    });
  }
}
