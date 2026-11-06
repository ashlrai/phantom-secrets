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
import { pathUpdateHarness } from './lib/installer-path-harness.mjs';

// Preserve unrelated comments and append only for marker near-matches.
const copies = {
  'scripts/install.sh': resolve(process.cwd(), 'scripts/install.sh'),
  'apps/web/public/install.sh': resolve(process.cwd(), 'apps/web/public/install.sh'),
};

const marker = '# phantom-secrets PATH';
const shells = {
  bash: {
    shell: '/bin/bash',
    rc: (h) => join(h, '.bashrc'),
    line: (b) => `export PATH="${b}:$PATH"`,
    setting: 'export EDITOR=vim',
    alias: 'alias ll="ls -la"',
  },
  zsh: {
    shell: '/bin/zsh',
    rc: (h) => join(h, '.zshrc'),
    line: (b) => `export PATH="${b}:$PATH"`,
    setting: 'export EDITOR=vim',
    alias: 'alias ll="ls -la"',
  },
  fish: {
    shell: '/usr/bin/fish',
    rc: (h) => join(h, '.config', 'fish', 'config.fish'),
    line: (b) => `set -gx PATH "${b}" $PATH`,
    setting: 'set -gx EDITOR vim',
    alias: 'alias ll "ls -la"',
  },
};

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

for (const [file, installer] of Object.entries(copies)) {
  const harness = pathUpdateHarness(readFileSync(installer, 'utf8'), file);
  for (const [shellName, config] of Object.entries(shells)) {
    for (const [layout, build] of layouts) {
      for (const finalNewline of [true, false]) {
        test(`${file} keeps unrelated ${shellName} comments unchanged (${layout}, ${finalNewline ? 'with' : 'without'} final newline)`, (t) => {
          const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-comment-')));
          t.after(() => rmSync(root, { recursive: true, force: true }));
          const home = join(root, 'home');
          const bin = join(root, 'live', 'bin');
          const rc = config.rc(home);
          mkdirSync(dirname(rc), { recursive: true });
          mkdirSync(bin, { recursive: true });
          const lines = build(config);
          const original = Buffer.from(lines.join('\n') + (finalNewline ? '\n' : ''), 'utf8');
          writeFileSync(rc, original, { mode: 0o600 });

          const first = runPathUpdate(harness, config, home, bin);
          assert.match(first.stdout, /added .* to PATH/);

          const updated = readFileSync(rc);
          assert.ok(updated.subarray(0, original.length).equals(original),
            'every pre-existing byte, including each unrelated comment, is unchanged');
          assert.equal(updated.subarray(original.length).toString('utf8'),
            `\n${marker}\n${config.line(bin)}\n`,
            'only the managed marker block is appended');
          for (const comment of lines.filter((l) => l.startsWith('#'))) {
            assert.equal(updated.indexOf(comment), original.indexOf(comment),
              `comment ${JSON.stringify(comment)} stays at the same offset`);
          }
          assert.equal(updated.toString('utf8').split(marker).length - 1, 1,
            'the only marker text in the file is the appended managed one');
          assert.equal(statSync(rc).mode & 0o777, 0o600,
            'the startup file keeps its permissions');
          assert.deepEqual(
            readdirSync(dirname(rc)).filter((name) => name.startsWith('.phantom-path.')),
            [],
            'no PATH-update temporary files are left behind',
          );

          const second = runPathUpdate(harness, config, home, bin);
          assert.match(second.stdout, /already wired into/);
          assert.ok(readFileSync(rc).equals(updated),
            'a repeat update changes nothing, comments included');
        });
      }
    }

    for (const comment of embeddedMarkerComments) {
      test(`${file} appends after a ${shellName} comment embedding the marker`, (t) => {
        const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-embedded-')));
        t.after(() => rmSync(root, { recursive: true, force: true }));
        const home = join(root, 'home');
        const bin = join(root, 'live', 'bin');
        const rc = config.rc(home);
        mkdirSync(dirname(rc), { recursive: true });
        mkdirSync(bin, { recursive: true });
        const original = Buffer.from(`${config.setting}\n${comment}\n`, 'utf8');
        writeFileSync(rc, original, { mode: 0o600 });

        const result = runPathUpdate(harness, config, home, bin);
        assert.match(result.stdout, /added .* to PATH/);
        assert.ok(readFileSync(rc).equals(Buffer.concat([original, Buffer.from(`\n${marker}\n${config.line(bin)}\n`)])),
          'embedded marker is preserved and a standalone marker block is appended');
        assert.deepEqual(
          readdirSync(dirname(rc)).filter((name) => name.startsWith('.phantom-path.')),
          [],
          'the update leaves no PATH-update temporary files',
        );
      });
    }
  }
}
