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

// Re-running the installer must never stack PATH entries. Each invocation of
// the shipped add_to_user_path appends the `# phantom-secrets PATH` marker
// plus one PATH line, then every later invocation short-circuits on the
// marker and reports "already wired" without editing the startup file. This
// drives the real function three times in a row — once to wire and twice to
// repeat — so the startup file provably ends with exactly one
// installer-managed block no matter how many times the update succeeds.
// Both branches are covered: an existing startup file keeps its content, and
// an absent one is created by the first update before the repeats run.
const copies = {
  'scripts/install.sh': resolve(import.meta.dirname, 'install.sh'),
  'apps/web/public/install.sh': resolve(import.meta.dirname, '..', 'apps', 'web', 'public', 'install.sh'),
};

// add_to_user_path runs under `set -euo pipefail` in the installer and calls
// these helpers; extract the exact same text so the exercised code is the
// shipped code. Single-line helpers like say() end on their opening line.
// Same extraction as installer-path-snapshot-spaces.test.mjs.
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

function pathUpdateHarness(source, file) {
  return ['set -euo pipefail', 'umask 077',
    ...['say', 'file_identity', 'file_link_count', 'add_to_user_path']
      .map((name) => extractFunction(source, name, file)),
    'add_to_user_path "$1"',
  ].join('\n');
}

const shells = {
  bash: {
    shell: '/bin/bash',
    rc: (home) => join(home, '.bashrc'),
    pathLine: (bin) => `export PATH="${bin}:$PATH"`,
  },
  zsh: {
    shell: '/bin/zsh',
    rc: (home) => join(home, '.zshrc'),
    pathLine: (bin) => `export PATH="${bin}:$PATH"`,
  },
  fish: {
    shell: '/usr/bin/fish',
    rc: (home) => join(home, '.config', 'fish', 'config.fish'),
    pathLine: (bin) => `set -gx PATH "${bin}" $PATH`,
  },
};

const marker = '# phantom-secrets PATH';

// One invocation of the extracted update — the same unit the installer runs
// at the end of every successful install.
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
    for (const finalNewline of [true, false]) {
      test(`${file} preserves unrelated ${shellName} settings in order (${finalNewline ? 'with' : 'without'} final newline)`, (t) => {
        const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-settings-')));
        t.after(() => rmSync(root, { recursive: true, force: true }));
        const home = join(root, 'home');
        const bin = join(root, 'bin');
        const rc = config.rc(home);
        mkdirSync(dirname(rc), { recursive: true });
        mkdirSync(bin, { recursive: true });
        const settings = shellName === 'fish'
          ? ['# personal settings', 'set -gx EDITOR vim', '', 'alias ll "ls -la"', 'set -g fish_greeting "hello world"']
          : ['# personal settings', 'export EDITOR=vim', '', 'alias ll="ls -la"', 'export GREETING="hello world"'];
        const original = settings.join('\n') + (finalNewline ? '\n' : '');
        writeFileSync(rc, original, { mode: 0o600 });

        const result = runPathUpdate(harness, config, home, bin);
        assert.match(result.stdout, /added .* to PATH/);
        assert.equal(readFileSync(rc, 'utf8'),
          `${original}\n${marker}\n${config.pathLine(bin)}\n`,
          'all original bytes remain in order before the appended PATH block');
      });
    }
    for (const scenario of ['pre-existing', 'absent']) {
      test(`${file} keeps one PATH entry across repeated ${shellName} updates (${scenario} startup file)`, (t) => {
        const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-idempotence-')));
        t.after(() => rmSync(root, { recursive: true, force: true }));
        const home = join(root, 'home');
        const bin = join(root, 'live', 'bin');
        const rc = config.rc(home);
        if (scenario === 'pre-existing') {
          mkdirSync(dirname(rc), { recursive: true });
          writeFileSync(rc, '# user shell config\nexport EDITOR=vim\n', { mode: 0o600 });
        } else {
          mkdirSync(home, { recursive: true });
        }
        mkdirSync(bin, { recursive: true });
        const rcParent = dirname(rc);

        const first = runPathUpdate(harness, config, home, bin);
        assert.match(first.stdout, /added .* to PATH/);
        const wired = readFileSync(rc, 'utf8');
        assert.ok(wired.includes(`\n${marker}\n`), 'the update added the marker');
        assert.ok(wired.includes(config.pathLine(bin)), 'the update added the PATH line');

        // Two more successful updates: each must recognize the marker, leave
        // the file byte-for-byte identical, and clean its temporary siblings.
        for (const repeat of [2, 3]) {
          const result = runPathUpdate(harness, config, home, bin);
          assert.match(result.stdout, /already wired into/);
          assert.doesNotMatch(result.stdout, /added .* to PATH/,
            `update ${repeat} must not append a second PATH block`);
          assert.equal(readFileSync(rc, 'utf8'), wired,
            `update ${repeat} left the startup file byte-for-byte unchanged`);
          assert.deepEqual(
            readdirSync(rcParent).filter((name) => name.startsWith('.phantom-path.')),
            [],
            `update ${repeat} left no PATH-update temporary files`,
          );
        }

        const lines = wired.split('\n');
        assert.equal(lines.filter((line) => line === marker).length, 1,
          'exactly one installer-managed PATH marker after repeated updates');
        assert.equal(lines.filter((line) => line === config.pathLine(bin)).length, 1,
          'exactly one installer-managed PATH line after repeated updates');
        assert.equal(statSync(rc).mode & 0o777, 0o600,
          'the startup file keeps private permissions');
        if (scenario === 'pre-existing') {
          assert.ok(lines.includes('export EDITOR=vim'),
            'pre-existing startup content is preserved');
        }
      });
    }
  }
}
