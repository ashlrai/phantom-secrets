import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { pathUpdateHarness } from './lib/installer-path-harness.mjs';
import {
  assertMode600,
  assertNoPathTempFiles,
  assertOriginalPrefixThenBlock,
  createStartupFixture,
  managedBlock,
  pathShellConfigs,
} from './lib/installer-path-test-fixtures.mjs';

// A `source` (or `.`) line is the startup-file construct most likely to sit
// next to a PATH edit, and the one a regex-based rewrite is most likely to
// mangle: it can carry `$VAR`, `${VAR}`, `${VAR:-default}`, `~`, quotes, and a
// trailing comment that itself mentions PATH. add_to_user_path must leave such
// a line byte-for-byte unchanged — same bytes at the same line index — and
// append only the managed marker block. The shipped text is extracted and run
// through the shared PATH-update fixture, as in the sibling PATH tests. A bash
// leg also sources the updated file so the preserved `source` line is proven
// to still evaluate, not just to still exist.
const copies = {
  'scripts/install.sh': resolve(import.meta.dirname, 'install.sh'),
  'apps/web/public/install.sh': resolve(import.meta.dirname, '..', 'apps', 'web', 'public', 'install.sh'),
};

const shells = pathShellConfigs({
  bash: {
    sources: [
      'source "${HOME}/.bash_extras"  # PATH extras live here',
      '. "$HOME/.cargo/env"',
    ],
  },
  zsh: {
    sources: [
      'source "${ZDOTDIR:-$HOME}/.zsh_local" # PATH extras live here',
      '. "$HOME/.cargo/env"',
    ],
  },
  fish: {
    sources: [
      'source "$HOME/.config/fish/local.fish" # PATH extras live here',
    ],
  },
});

const fixtureFor = (config) =>
  Buffer.from(`# user config\n${config.sources.join('\n')}\nexport EDITOR=vim\n`, 'utf8');

for (const [file, installer] of Object.entries(copies)) {
  const harness = pathUpdateHarness(readFileSync(installer, 'utf8'), file);
  for (const [name, config] of Object.entries(shells)) {
    test(`${file} keeps an unrelated ${name} source line unchanged when updating PATH`, (t) => {
      const original = fixtureFor(config);
      const { rc, bin, run } = createStartupFixture(t, {
        prefix: 'phantom-path-source-', harness, config, content: original,
      });

      const result = run();
      assert.match(result.stdout, /added .* to PATH/);

      const after = assertOriginalPrefixThenBlock(rc, original, config, bin, {
        prefix: 'every original byte, source line included, is unchanged at its offset',
        appended: 'only the managed block is appended',
      });

      const originalLines = original.toString('utf8').split('\n');
      const updatedLines = after.toString('utf8').split('\n');
      for (const line of config.sources) {
        const index = originalLines.indexOf(line);
        assert.ok(index >= 0, `fixture contains ${JSON.stringify(line)}`);
        assert.equal(updatedLines[index], line,
          'the source line keeps its bytes at its original line index');
        assert.equal(updatedLines.filter((l) => l === line).length, 1,
          `source line ${JSON.stringify(line)} appears exactly once`);
      }
      assertMode600(rc);
      assertNoPathTempFiles(rc);
    });

    test(`${file} leaves a wired ${name} file with a source line byte-for-byte identical`, (t) => {
      let original;
      const { rc, run } = createStartupFixture(t, {
        prefix: 'phantom-path-source-wired-', harness, config,
        content: ({ bin }) => {
          original = Buffer.concat([
            fixtureFor(config),
            Buffer.from(managedBlock(config, bin)),
          ]);
          return original;
        },
      });

      const result = run();
      assert.match(result.stdout, /already wired into/);
      assert.ok(readFileSync(rc).equals(original),
        'the no-op path leaves every byte, source line included, unchanged');
    });
  }

  test(`${file} leaves a bash source line working after the update`, (t) => {
    const config = shells.bash;
    const { home, bin, run } = createStartupFixture(t, {
      prefix: 'phantom-path-source-eval-', harness, config,
      content: fixtureFor(config),
    });
    writeFileSync(join(home, '.bash_extras'),
      'PHANTOM_TEST_SOURCED=yes\nexport PATH="$HOME/extra/bin:$PATH"\n',
      { mode: 0o600 });

    const result = run();
    assert.match(result.stdout, /added .* to PATH/);

    // Source the updated file in a clean bash: the preserved source line must
    // still evaluate, and the installer bin dir must lead PATH.
    const check = spawnSync('/bin/bash', [
      '--noprofile', '--norc', '-c',
      '. "$HOME/.bashrc" && [[ "$PHANTOM_TEST_SOURCED" == yes ]] && '
      + '[[ "$PATH" == "$1:"* ]] && [[ "$PATH" == *"$HOME/extra/bin:"* ]]',
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
