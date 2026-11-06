import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { pathUpdateHarness } from './lib/installer-path-harness.mjs';
import {
  assertNoPathTempFiles,
  assertOriginalPrefixThenBlock,
  createStartupFixture,
  pathShellConfigs,
} from './lib/installer-path-test-fixtures.mjs';

// Startup files routinely pull in other files: nvm, cargo, oh-my-zsh, local
// overrides. Those unrelated `source` lines — in both `source` and `.`
// spellings, guarded and conditional forms, paths with spaces, and one
// phantom-path lookalike that must not satisfy the marker grep — are exactly
// the lines a careless rewrite would mangle or misread as PATH wiring. The
// update may only append the managed block, and a second run must no-op on
// "already wired" without touching them. A bash leg then re-sources the
// replaced file to prove the `source` line still executes, not just survives:
// the update swaps in a new inode via mv -f, it is not an in-place edit.
const copies = {
  'scripts/install.sh': resolve(import.meta.dirname, 'install.sh'),
  'apps/web/public/install.sh': resolve(import.meta.dirname, '..', 'apps', 'web', 'public', 'install.sh'),
};

const shells = pathShellConfigs({
  bash: {
    sources: [
      '# user shell config',
      'source "$HOME/.extra_aliases.sh"',
      '. "$HOME/.cargo/env"',
      'source ~/.bash_extras 2>/dev/null || true',
      '[ -r "$HOME/.pathrc" ] && source "$HOME/.pathrc" # loads my PATH tweaks',
      'source "$HOME/dir with spaces/env  file.sh" # café',
      'source "$HOME/.phantom-paths.sh" # lookalike, not the managed block',
      'export EDITOR=vim',
    ],
  },
  zsh: {
    sources: [
      '# user shell config',
      'source "$HOME/.zsh_local"',
      '. "/opt/tool/env.zsh"',
      'source ~/.oh-my-zsh/oh-my-zsh.sh 2>/dev/null || true',
      '[ -r "$HOME/.pathrc" ] && source "$HOME/.pathrc" # loads my PATH tweaks',
      'source "$HOME/.phantom-paths.sh" # lookalike, not the managed block',
      'export EDITOR=vim',
    ],
  },
  fish: {
    sources: [
      '# user shell config',
      'source ~/.config/fish/conf.d/local.fish',
      'test -f ~/.private.fish; and source ~/.private.fish',
      'source "$HOME/.pathrc.fish" # loads my PATH tweaks',
      'source "$HOME/dir with spaces/extra  fish.fish" # café',
      'source "$HOME/.phantom-paths.fish" # lookalike, not the managed block',
      'set -gx EDITOR vim',
    ],
  },
});

for (const [file, installer] of Object.entries(copies)) {
  const harness = pathUpdateHarness(readFileSync(installer, 'utf8'), file);
  for (const [shellName, config] of Object.entries(shells)) {
    for (const finalNewline of [true, false]) {
      test(`${file} keeps every unrelated ${shellName} source line byte-for-byte (${finalNewline ? 'with' : 'without'} final newline)`, (t) => {
        const original = Buffer.from(
          config.sources.join('\n') + (finalNewline ? '\n' : ''), 'utf8');
        const { rc, bin, run } = createStartupFixture(t, {
          prefix: 'phantom-path-source-', harness, config, content: original,
        });

        const result = run();
        assert.match(result.stdout, /added .* to PATH/);

        const after = assertOriginalPrefixThenBlock(rc, original, config, bin, {
          prefix: 'every original byte, source lines included, is unchanged at its offset',
          appended: 'only the managed block is appended',
        });
        const updatedText = after.toString('utf8');
        for (const line of config.sources) {
          assert.equal(updatedText.split('\n').filter((l) => l === line).length, 1,
            `source line ${JSON.stringify(line)} is intact and appears exactly once`);
        }
        assertNoPathTempFiles(rc);

        const second = run();
        assert.match(second.stdout, /already wired into/);
        assert.ok(readFileSync(rc).equals(after),
          'the already-wired no-op leaves the file, source lines included, byte-identical');
      });
    }
  }

  test(`${file} keeps a live bash source line working after the update`, (t) => {
    const config = shells.bash;
    const { home, rc, bin, run } = createStartupFixture(t, {
      prefix: 'phantom-path-source-eval-', harness, config,
      content: [
        '# user shell config',
        'source "$HOME/.sourced_env.sh"',
        '[ -r "$HOME/.pathrc" ] && source "$HOME/.pathrc" # guarded, absent',
        'export EDITOR=vim',
        '',
      ].join('\n'),
    });
    writeFileSync(join(home, '.sourced_env.sh'),
      'SOURCED_ENV_LOADED=yes\nexport PATH="/opt/sourced/bin:$PATH"\n', { mode: 0o600 });

    const result = run();
    assert.match(result.stdout, /added .* to PATH/);

    // Source the updated file in a clean bash: the sourced file must still
    // load through the replaced rc, and both PATH entries must be live with
    // the installer bin dir first.
    const check = spawnSync('/bin/bash', [
      '--noprofile', '--norc', '-c',
      '. "$HOME/.bashrc" && '
      + '[[ "$SOURCED_ENV_LOADED" == yes ]] && [[ "$EDITOR" == vim ]] && '
      + '[[ "$PATH" == "$1:"* ]] && [[ "$PATH" == *":/opt/sourced/bin:"* ]]',
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
