import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { pathUpdateHarness } from './lib/installer-path-harness.mjs';

// An unrelated line with a literal dollar sign must survive the PATH update
// byte-for-byte. These shapes break rewrites that expand variables, pass the
// line through printf/sed/awk, or treat `$` as a regex anchor or `&`/`\1`
// replacement token: a lone `$`, `$$`, positional and special parameters,
// escaped and ANSI-C quoted dollars, `${...}` forms, a printf-looking line,
// and a trailing dollar. Checked on the append path and the already-wired path.
const copies = {
  'scripts/install.sh': resolve(import.meta.dirname, 'install.sh'),
  'apps/web/public/install.sh': resolve(import.meta.dirname, '..', 'apps', 'web', 'public', 'install.sh'),
};

const harnessFor = pathUpdateHarness;

const marker = '# phantom-secrets PATH';
const shells = {
  bash: { shell: '/bin/bash', rc: (h) => join(h, '.bashrc'), line: (b) => `export PATH="${b}:$PATH"` },
  zsh: { shell: '/bin/zsh', rc: (h) => join(h, '.zshrc'), line: (b) => `export PATH="${b}:$PATH"` },
  fish: { shell: '/usr/bin/fish', rc: (h) => join(h, '.config', 'fish', 'config.fish'),
    line: (b) => `set -gx PATH "${b}" $PATH` },
};

const dollarLines = [
  '$',
  '$$',
  'echo $1 $@ $* $# $? $! $0',
  "export PRICE='cost: \\$5 and $'",
  "export NL=$'a\\nb$'",
  'export HOME_COPY=${HOME:-/tmp}/${USER}$',
  'export PATH_COPY=$PATH',
  'printf "%s $%d\\n" "$HOME" 5 # $& \\1',
  'export SED_ISH=s/^$/x/',
];

for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  for (const [name, config] of Object.entries(shells)) {
    for (const wired of [false, true]) {
      test(`${file} keeps literal-dollar lines byte-for-byte (${name}, ${wired ? 'already wired' : 'PATH appended'})`, (t) => {
        const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-dollar-')));
        t.after(() => rmSync(root, { recursive: true, force: true }));
        const home = join(root, 'home');
        const bin = join(root, 'live', 'bin');
        const rc = config.rc(home);
        mkdirSync(dirname(rc), { recursive: true });
        mkdirSync(bin, { recursive: true });

        const body = `# mine\n${dollarLines.join('\n')}\n`;
        const original = Buffer.from(
          wired ? `${body}\n${marker}\n${config.line(bin)}\n${dollarLines.join('\n')}\n` : body, 'utf8');
        writeFileSync(rc, original, { mode: 0o600 });

        const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
          encoding: 'utf8',
          timeout: 30000,
          env: { HOME: home, SHELL: config.shell, PATH: '/usr/bin:/bin' },
        });
        assert.ifError(result.error);
        assert.equal(result.status, 0, result.stderr);

        const after = readFileSync(rc);
        if (wired) {
          assert.match(result.stdout, /already wired into/);
          assert.ok(after.equals(original), 'the startup file is byte-for-byte unchanged');
        } else {
          assert.match(result.stdout, /added .* to PATH/);
          assert.ok(after.subarray(0, original.length).equals(original), 'original bytes are an unchanged prefix');
          assert.equal(after.subarray(original.length).toString('utf8'),
            `\n${marker}\n${config.line(bin)}\n`, 'only the managed block is appended');
        }
        const lines = after.toString('utf8').split('\n');
        for (const line of dollarLines) assert.ok(lines.includes(line), `intact: ${line}`);
      });
    }
  }
}

// Restored original per-shell fixtures and assertions.
{
// An unrelated startup-file line that merely contains a literal dollar sign
// must survive the PATH update byte-for-byte. Each shell's fixture line packs
// the `$` forms a rewrite of the file could expand or misanchor — single-quoted
// `$(...)`, `${...}`, `\$`, `$VAR`, and `$5` — inside a realistic prompt or
// greeting line. The file is compared as raw Buffers: every original byte must
// be an unchanged prefix and only the managed marker block may be appended.
// A second update must change nothing, and when the PATH entry is already
// wired the whole file — dollar line included — stays byte-identical.
const copies = {
  'scripts/install.sh': resolve(import.meta.dirname, 'install.sh'),
  'apps/web/public/install.sh': resolve(import.meta.dirname, '..', 'apps', 'web', 'public', 'install.sh'),
};

// Same extraction as installer-path-unrelated-export.test.mjs: run the shipped text.
const harnessFor = pathUpdateHarness;

const marker = '# phantom-secrets PATH';
const shells = {
  bash: {
    shell: '/bin/bash',
    rc: (h) => join(h, '.bashrc'),
    line: (b) => `export PATH="${b}:$PATH"`,
    dollar: Buffer.from(`export PS1='[\\u@\\h \\W]$(__git_ps1)\\$ '`),
  },
  zsh: {
    shell: '/bin/zsh',
    rc: (h) => join(h, '.zshrc'),
    line: (b) => `export PATH="${b}:$PATH"`,
    dollar: Buffer.from(`export PROMPT='\${ret_status} %{$fg[cyan]%}%c%{$reset_color%} $(git_prompt_info)'`),
  },
  fish: {
    shell: '/usr/bin/fish',
    rc: (h) => join(h, '.config', 'fish', 'config.fish'),
    line: (b) => `set -gx PATH "${b}" $PATH`,
    dollar: Buffer.from(`set -g fish_greeting 'Welcome, $USER! Balance: $5'`),
  },
};

const endings = { 'with final newline': '\n', 'without final newline': '' };

for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  for (const [shellName, config] of Object.entries(shells)) {
    for (const [ending, tail] of Object.entries(endings)) {
      test(`${file} keeps an unrelated ${shellName} line with a literal $ byte-for-byte (${ending})`, (t) => {
        const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-dollar-')));
        t.after(() => rmSync(root, { recursive: true, force: true }));
        const home = join(root, 'home');
        const bin = join(root, 'live', 'bin');
        const rc = config.rc(home);
        mkdirSync(dirname(rc), { recursive: true });
        mkdirSync(bin, { recursive: true });
        const original = Buffer.concat([Buffer.from('# mine\n'), config.dollar, Buffer.from(tail)]);
        writeFileSync(rc, original, { mode: 0o600 });

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

        const first = run();
        assert.match(first.stdout, /added .* to PATH/);
        const updated = readFileSync(rc);
        assert.ok(updated.subarray(0, original.length).equals(original),
          'the literal-dollar line and every other original byte are an unchanged prefix');
        assert.equal(updated.subarray(original.length).toString('utf8'),
          `\n${marker}\n${config.line(bin)}\n`, 'only the managed block is appended');
        assert.equal(updated.indexOf(config.dollar), updated.lastIndexOf(config.dollar),
          'the dollar-sign line appears exactly once');
        assert.equal(statSync(rc).mode & 0o777, 0o600,
          'the startup file keeps its permissions');
        assert.deepEqual(
          readdirSync(dirname(rc)).filter((name) => name.startsWith('.phantom-path.')),
          [],
          'no PATH-update temporary files are left behind',
        );

        run();
        assert.ok(readFileSync(rc).equals(updated), 'a second update changes nothing');
      });
    }

    test(`${file} keeps an unrelated ${shellName} line with a literal $ when the PATH entry is already wired`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-dollar-wired-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      const rc = config.rc(home);
      mkdirSync(dirname(rc), { recursive: true });
      mkdirSync(bin, { recursive: true });
      const original = Buffer.concat([
        Buffer.from('# mine\n'), config.dollar,
        Buffer.from(`\n${marker}\n${config.line(bin)}\n`),
      ]);
      writeFileSync(rc, original, { mode: 0o600 });

      const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
        encoding: 'utf8',
        timeout: 30000,
        env: { HOME: home, SHELL: config.shell, PATH: '/usr/bin:/bin' },
      });
      assert.ifError(result.error);
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, /already wired into/);
      assert.ok(readFileSync(rc).equals(original),
        'the whole startup file, dollar line included, is byte-for-byte unchanged');
    });
  }
}

}
