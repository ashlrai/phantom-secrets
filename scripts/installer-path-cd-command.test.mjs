import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { pathUpdateHarness } from './lib/installer-path-harness.mjs';
import {
  assertMode600,
  assertNoPathTempFiles,
  assertOriginalPrefixThenBlock,
  createStartupFixture,
  marker,
  pathShellConfigs,
} from './lib/installer-path-test-fixtures.mjs';

// A user who changes directory from a startup file must keep every `cd`
// command byte-for-byte when the installer wires its bin dir into PATH: the
// update may only append the managed marker block after the original bytes.
// This drives the shipped add_to_user_path over startup files holding the
// common `cd` forms — bare `cd`, `cd ..`, `cd -`, tilde, variable and quoted
// targets — plus a `cd` whose target directory name contains the marker text,
// proving the whole-line marker check is not fooled into skipping the update.
// The shipped text of add_to_user_path is extracted and run through the
// shared PATH-update fixture, as in the sibling PATH tests.
const installers = {
  'scripts/install.sh': new URL('install.sh', import.meta.url),
  'apps/web/public/install.sh': new URL('../apps/web/public/install.sh', import.meta.url),
};

const shells = pathShellConfigs({});

// Unrelated `cd` commands valid in bash, zsh and fish: bare, parent, previous,
// tilde, variable and quoted-space targets. None names the managed block.
const cdLines = [
  'cd',
  'cd ..',
  'cd -',
  'cd ~/projects',
  'cd "$WORKDIR"',
  "cd '/opt/some dir'",
];

// Final-line endings the original file may have: the commands must survive each.
const endings = { 'final newline': '\n', 'no final newline': '' };

const appendedOnly = {
  prefix: 'original bytes are an unchanged prefix',
  appended: 'only the marker and PATH lines are appended',
};

for (const [file, url] of Object.entries(installers)) {
  const harness = pathUpdateHarness(readFileSync(fileURLToPath(url), 'utf8'), file);
  for (const [name, config] of Object.entries(shells)) {
    for (const [ending, tail] of Object.entries(endings)) {
      test(`${file} keeps unrelated cd commands byte-for-byte updating a ${name} PATH (${ending})`, (t) => {
        const fixture = createStartupFixture(t, {
          prefix: 'phantom-path-cd-', harness, config,
          content: Buffer.from(`# user config\n${cdLines.join('\n')}\nexport NOTE=1${tail}`, 'utf8'),
        });
        const original = readFileSync(fixture.rc);

        const result = fixture.run();
        assert.match(result.stdout, /added .* to PATH/);

        const after = assertOriginalPrefixThenBlock(fixture.rc, original, config, fixture.bin, appendedOnly);
        const lines = after.toString('utf8').split('\n');
        for (const cd of cdLines) {
          assert.equal(lines.filter((l) => l === cd).length, 1,
            `unrelated cd command ${JSON.stringify(cd)} is unchanged exactly once`);
        }
        assertMode600(fixture.rc);
        assertNoPathTempFiles(fixture.rc);
      });
    }

    test(`${file} keeps a lone cd command with no final newline when updating a ${name} PATH`, (t) => {
      const fixture = createStartupFixture(t, {
        prefix: 'phantom-path-cd-lone-', harness, config,
        content: Buffer.from('cd "$HOME/projects"', 'utf8'),
      });
      const original = readFileSync(fixture.rc);

      const result = fixture.run();
      assert.match(result.stdout, /added .* to PATH/);
      assertOriginalPrefixThenBlock(fixture.rc, original, config, fixture.bin, appendedOnly);
      assertMode600(fixture.rc);
      assertNoPathTempFiles(fixture.rc);
    });

    // A `cd` whose target directory name contains the marker text is not the
    // managed block: only a line that is exactly the marker proves the
    // installer already ran. The update must still append, and a repeat must
    // short-circuit on the real marker without touching the file.
    test(`${file} wires PATH past a ${name} cd whose target mentions the marker`, (t) => {
      const cdMention = `cd "$HOME/${marker}"`;
      const fixture = createStartupFixture(t, {
        prefix: 'phantom-path-cd-mention-', harness, config,
        content: Buffer.from(`# user config\n${cdMention}\nexport NOTE=1\n`, 'utf8'),
      });
      const original = readFileSync(fixture.rc);
      mkdirSync(join(fixture.home, marker), { recursive: true });

      const result = fixture.run();
      assert.match(result.stdout, /added .* to PATH/);
      const after = assertOriginalPrefixThenBlock(fixture.rc, original, config, fixture.bin, appendedOnly);
      const lines = after.toString('utf8').split('\n');
      assert.equal(lines.filter((l) => l === marker).length, 1,
        'exactly one real marker line after the update');
      assert.ok(lines.includes(cdMention), 'the marker-mentioning cd command is intact');
      assertMode600(fixture.rc);
      assertNoPathTempFiles(fixture.rc);

      const second = fixture.run();
      assert.match(second.stdout, /already wired into/);
      assert.doesNotMatch(second.stdout, /added .* to PATH/,
        'the repeat update must not append a second PATH block');
      assert.ok(readFileSync(fixture.rc).equals(after),
        'the repeat update leaves the file byte-for-byte unchanged');
      assertNoPathTempFiles(fixture.rc);
    });
  }

  // The preserved `cd` must still evaluate: sourcing the updated bash startup
  // file lands in its target while the appended PATH line stays live.
  test(`${file} leaves a cd command working after the bash PATH update`, (t) => {
    const config = shells.bash;
    const fixture = createStartupFixture(t, {
      prefix: 'phantom-path-cd-eval-', harness, config,
      content: '# user config\ncd "$HOME/projects"\nexport NOTE=1\n',
    });
    const projects = join(fixture.home, 'projects');
    mkdirSync(projects, { recursive: true });

    const result = fixture.run();
    assert.match(result.stdout, /added .* to PATH/);

    const check = spawnSync('/bin/bash', [
      '--noprofile', '--norc', '-c',
      '. "$HOME/.bashrc" && [[ "$PATH" == "$1:"* ]] && pwd -P',
      'path-test', fixture.bin,
    ], {
      encoding: 'utf8', timeout: 30000,
      env: { HOME: fixture.home, PATH: '/usr/bin:/bin' },
    });
    assert.ifError(check.error);
    assert.equal(check.status, 0, check.stderr);
    assert.equal(check.stdout.trim(), projects);
    assertMode600(fixture.rc);
    assertNoPathTempFiles(fixture.rc);
  });
}
