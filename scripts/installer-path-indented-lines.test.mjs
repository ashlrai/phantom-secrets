import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

// Startup-file lines with leading indentation — four and eight spaces, tabs, a
// space/tab mix, an indented comment, an indented conditional body, and
// indented lookalikes of the managed marker and PATH line — must survive the
// PATH update byte-for-byte, compared as raw Buffers. The indented lookalikes
// double as a guard on the marker check: grep -qxF matches whole lines only,
// so an indented "# phantom-secrets PATH" must neither be treated as the
// managed marker nor suppress the append. The original bytes stay an exact
// prefix, the only addition is the managed block, a second update changes
// nothing, and an already-wired file is left alone. Runs the shipped
// add_to_user_path from both installer copies.
const installers = {
  'scripts/install.sh': new URL('install.sh', import.meta.url),
  'apps/web/public/install.sh': new URL('../apps/web/public/install.sh', import.meta.url),
};

const marker = '# phantom-secrets PATH';
const shells = {
  bash: {
    shell: '/bin/bash', rc: (h) => join(h, '.bashrc'),
    line: (b) => `export PATH="${b}:$PATH"`,
    indented: [
      '# user config',
      'if [ -d "$HOME/.local/bin" ]; then',
      '    export PATH="$HOME/.local/bin:$PATH"',
      'fi',
      '        export EDITOR=vim',
      '\tmkcd() { mkdir -p "$1" && cd "$1"; }',
      ' \t export MIXED="space tab space"',
      '  # indented comment',
      `    ${marker}`,
    ],
  },
  zsh: {
    shell: '/bin/zsh', rc: (h) => join(h, '.zshrc'),
    line: (b) => `export PATH="${b}:$PATH"`,
    indented: [
      '# user config',
      'if [ -d "$HOME/.local/bin" ]; then',
      '    export PATH="$HOME/.local/bin:$PATH"',
      'fi',
      '        export EDITOR=vim',
      '\tmkcd() { mkdir -p "$1" && cd "$1"; }',
      ' \t export MIXED="space tab space"',
      '  # indented comment',
      `    ${marker}`,
    ],
  },
  fish: {
    shell: '/usr/bin/fish', rc: (h) => join(h, '.config', 'fish', 'config.fish'),
    line: (b) => `set -gx PATH "${b}" $PATH`,
    indented: [
      '# user config',
      'if test -d ~/.local/bin',
      '    set -gx PATH ~/.local/bin $PATH',
      'end',
      '        set -gx EDITOR vim',
      '\tfunction mkcd; mkdir -p $argv[1]; and cd $argv[1]; end',
      ' \t set -gx MIXED "space tab space"',
      '  # indented comment',
      `    ${marker}`,
    ],
  },
};

function extractFunction(source, name, file) {
  const start = source.indexOf(`${name}()`);
  assert.ok(start >= 0, `${file}: locate ${name}`);
  const lineEnd = source.indexOf('\n', start);
  if (source.slice(start, lineEnd).trimEnd().endsWith('}')) return source.slice(start, lineEnd + 1);
  const end = source.indexOf('\n}\n', start);
  assert.ok(end > start, `${file}: locate end of ${name}`);
  return source.slice(start, end + 3);
}

for (const [file, url] of Object.entries(installers)) {
  const source = readFileSync(fileURLToPath(url), 'utf8');
  const harness = ['set -euo pipefail', 'umask 077',
    ...['say', 'file_identity', 'file_link_count', 'add_to_user_path']
      .map((name) => extractFunction(source, name, file)),
    'add_to_user_path "$1"',
  ].join('\n');

  for (const [shellName, config] of Object.entries(shells)) {
    const setup = (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), `phantom-path-indent-${shellName}-`)));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      const rc = config.rc(home);
      mkdirSync(dirname(rc), { recursive: true });
      mkdirSync(bin, { recursive: true });
      const run = () => {
        const r = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
          encoding: 'utf8',
          timeout: 30000,
          env: { HOME: home, SHELL: config.shell, PATH: '/usr/bin:/bin' },
        });
        assert.ifError(r.error);
        assert.equal(r.status, 0, r.stderr);
        return r;
      };
      return { rc, bin, run };
    };

    for (const trailing of ['\n', '']) {
      test(`${file} keeps indented ${shellName} lines byte-for-byte (${trailing ? 'with' : 'without'} final newline)`, (t) => {
        const { rc, bin, run } = setup(t);
        const original = Buffer.from(config.indented.join('\n') + trailing);
        writeFileSync(rc, original, { mode: 0o600 });

        assert.match(run().stdout, /added .* to PATH/);
        const updated = readFileSync(rc);
        assert.ok(updated.subarray(0, original.length).equals(original),
          'every indented line keeps its exact bytes as an unchanged prefix');
        assert.equal(updated.subarray(original.length).toString('utf8'),
          `\n${marker}\n${config.line(bin)}\n`, 'only the managed block is appended');

        // The indented marker lookalike stays indented and still does not
        // satisfy the whole-line marker check on its own.
        const indentedMarker = `    ${marker}`;
        assert.equal(
          readFileSync(rc, 'utf8').split('\n').filter((l) => l === indentedMarker).length,
          1, 'the indented marker lookalike is preserved exactly once');

        run();
        assert.ok(readFileSync(rc).equals(updated), 'a second update changes nothing');
        assert.deepEqual(
          readdirSync(dirname(rc)).filter((name) => name.startsWith('.phantom-path.')),
          [], 'no PATH-update temporary files are left behind');
      });
    }

    test(`${file} keeps indented ${shellName} lines byte-for-byte when the PATH entry is already wired`, (t) => {
      const { rc, bin, run } = setup(t);
      const original = Buffer.from(`${config.indented.join('\n')}\n${marker}\n${config.line(bin)}\n`);
      writeFileSync(rc, original, { mode: 0o600 });

      assert.match(run().stdout, /already wired into/);
      assert.ok(readFileSync(rc).equals(original), 'the whole startup file is byte-for-byte unchanged');
    });
  }
}
