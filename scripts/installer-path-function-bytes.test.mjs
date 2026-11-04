import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';

// An unrelated shell function in the startup file must survive the PATH update
// byte-for-byte, compared as raw Buffers (not decoded text), including tabs,
// CRLF line endings, a lone CR, a non-UTF-8 byte, and a missing final newline.
// A second update must leave the whole file untouched. The bash leg covers
// .bashrc; the zsh and fish legs prove the same byte preservation for .zshrc
// and an `end`-terminated fish function in .config/fish/config.fish, where the
// managed PATH line is fish syntax. When the marker is already present the
// update is a no-op and the file — function included — stays byte-identical.
// Three more legs pin the same guarantee from other angles: a function in the
// middle of the file keeps the lines after it equally untouched (the update
// appends, never inserts), an indented in-body mention of the marker text is
// not the line-exact marker `grep -qxF` looks for so the update still wires
// and leaves the mentioning function alone, and a sourced bash probe shows the
// function's declared definition and observable output are identical before
// and after the update — unchanged means still callable, not just still
// present.
const copies = {
  'scripts/install.sh': resolve(import.meta.dirname, 'install.sh'),
  'apps/web/public/install.sh': resolve(import.meta.dirname, '..', 'apps', 'web', 'public', 'install.sh'),
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

const harnessFor = (source, file) => ['set -euo pipefail', 'umask 077',
  ...['say', 'file_identity', 'file_link_count', 'add_to_user_path']
    .map((name) => extractFunction(source, name, file)),
  'add_to_user_path "$1"',
].join('\n');

const fn = Buffer.concat([
  Buffer.from('my_func() {\r\n\techo "a\tb"  \r\n\tprintf \'%s\\n\' "caf'),
  Buffer.from([0xe9, 0x0d]),
  Buffer.from('"\r\n}'),
]);

const marker = '# phantom-secrets PATH';
const shells = {
  bash: {
    shell: '/bin/bash', rc: (h) => join(h, '.bashrc'),
    line: (b) => `export PATH="${b}:$PATH"`,
    prefix: Buffer.from('export A=1\n'), fn,
    after: Buffer.from('\nexport AFTER_FN=kept\nalias h="history"\n'),
    mentionFn: Buffer.from('note() {\n\t# phantom-secrets PATH\n\texport PATH="/opt/note-tools/bin:$PATH"\n\tprintf \'%s\\n\' "noted"\n}'),
  },
  zsh: {
    shell: '/bin/zsh', rc: (h) => join(h, '.zshrc'),
    line: (b) => `export PATH="${b}:$PATH"`,
    prefix: Buffer.from('export A=1\n'),
    fn: Buffer.concat([
      Buffer.from('zfn() {\r\n\tlocal -x opted="a\tb"  \r\n\tprint -r -- "caf'),
      Buffer.from([0xe9, 0x0d]),
      Buffer.from('"\r\n}'),
    ]),
    after: Buffer.from('\nexport AFTER_FN=kept\nalias h="history"\n'),
    mentionFn: Buffer.from('znote() {\n\t# phantom-secrets PATH\n\texport PATH="/opt/znote-tools/bin:$PATH"\n\tprint -r -- "noted"\n}'),
  },
  fish: {
    shell: '/usr/bin/fish', rc: (h) => join(h, '.config', 'fish', 'config.fish'),
    line: (b) => `set -gx PATH "${b}" $PATH`,
    prefix: Buffer.from('set -gx EDITOR vim\n'),
    fn: Buffer.concat([
      Buffer.from('function ffn\r\n\tset -l picked "a\tb"  \r\n\tprintf \'%s\\n\' "caf'),
      Buffer.from([0xe9, 0x0d]),
      Buffer.from('"\r\nend'),
    ]),
    after: Buffer.from('\nset -gx AFTER_FN kept\nalias h "history"\n'),
    mentionFn: Buffer.from('function fnote\n\t# phantom-secrets PATH\n\tset -gx PATH /opt/fnote-tools/bin $PATH\n\tprintf \'%s\\n\' "noted"\nend'),
  },
};

for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  for (const trailing of ['\n', '']) {
    test(`${file} keeps an unrelated shell function byte-for-byte (${trailing ? 'with' : 'without'} final newline)`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-fnbytes-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      mkdirSync(home, { recursive: true });
      mkdirSync(bin, { recursive: true });
      const rc = join(home, '.bashrc');
      const original = Buffer.concat([Buffer.from('export A=1\n'), fn, Buffer.from(trailing)]);
      writeFileSync(rc, original, { mode: 0o600 });

      const run = () => {
        const r = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
          encoding: 'utf8',
          timeout: 30000,
          env: { HOME: home, SHELL: '/bin/bash', PATH: '/usr/bin:/bin' },
        });
        assert.ifError(r.error);
        assert.equal(r.status, 0, r.stderr);
      };

      run();
      const updated = readFileSync(rc);
      assert.ok(updated.subarray(0, original.length).equals(original),
        'original bytes are an exact prefix of the updated file');
      assert.ok(updated.includes(fn), 'the function bytes are intact');
      assert.equal(updated.indexOf(fn), updated.lastIndexOf(fn), 'the function appears once');

      run();
      assert.ok(readFileSync(rc).equals(updated), 'a second update changes nothing');
    });
  }

  for (const shellName of ['zsh', 'fish']) {
    const config = shells[shellName];
    for (const trailing of ['\n', '']) {
      test(`${file} keeps an unrelated ${shellName} function byte-for-byte (${trailing ? 'with' : 'without'} final newline)`, (t) => {
        const root = realpathSync(mkdtempSync(join(tmpdir(), `phantom-path-fnbytes-${shellName}-`)));
        t.after(() => rmSync(root, { recursive: true, force: true }));
        const home = join(root, 'home');
        const bin = join(root, 'live', 'bin');
        const rc = config.rc(home);
        mkdirSync(dirname(rc), { recursive: true });
        mkdirSync(bin, { recursive: true });
        const original = Buffer.concat([config.prefix, config.fn, Buffer.from(trailing)]);
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
          'original bytes are an exact prefix of the updated file');
        assert.ok(updated.includes(config.fn), 'the function bytes are intact');
        assert.equal(updated.indexOf(config.fn), updated.lastIndexOf(config.fn),
          'the function appears once');
        assert.equal(updated.subarray(original.length).toString('utf8'),
          `\n${marker}\n${config.line(bin)}\n`, 'only the managed block is appended');

        run();
        assert.ok(readFileSync(rc).equals(updated), 'a second update changes nothing');
      });
    }
  }

  for (const [shellName, config] of Object.entries(shells)) {
    test(`${file} keeps an unrelated ${shellName} function byte-for-byte when the PATH entry is already wired`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), `phantom-path-fnbytes-wired-${shellName}-`)));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      const rc = config.rc(home);
      mkdirSync(dirname(rc), { recursive: true });
      mkdirSync(bin, { recursive: true });
      const original = Buffer.concat([
        config.prefix, config.fn,
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
        'the whole startup file, function included, is byte-for-byte unchanged');
    });
  }

  for (const [shellName, config] of Object.entries(shells)) {
    test(`${file} keeps an unrelated ${shellName} function byte-for-byte with content after it`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), `phantom-path-fnmid-${shellName}-`)));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      const rc = config.rc(home);
      mkdirSync(dirname(rc), { recursive: true });
      mkdirSync(bin, { recursive: true });
      const original = Buffer.concat([config.prefix, config.fn, config.after]);
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

      const expected = Buffer.concat([
        original,
        Buffer.from(`\n${marker}\n${config.line(bin)}\n`),
      ]);
      assert.match(run().stdout, /added .* to PATH/);
      assert.ok(readFileSync(rc).equals(expected),
        'the function and every line after it are unchanged; only the managed block is appended');

      run();
      assert.ok(readFileSync(rc).equals(expected), 'a second update changes nothing');
    });
  }

  for (const [shellName, config] of Object.entries(shells)) {
    test(`${file} still wires a ${shellName} file whose unrelated function only mentions the marker in its body`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), `phantom-path-fnmention-${shellName}-`)));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      const rc = config.rc(home);
      mkdirSync(dirname(rc), { recursive: true });
      mkdirSync(bin, { recursive: true });
      const original = Buffer.concat([config.prefix, config.mentionFn, Buffer.from('\n')]);
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

      const expected = Buffer.concat([
        original,
        Buffer.from(`\n${marker}\n${config.line(bin)}\n`),
      ]);
      // The function's body holds an indented `# phantom-secrets PATH` line.
      // The marker check is line-exact (`grep -qxF`), so the mention must not
      // read as already wired: the update appends its block and keeps every
      // byte of the mentioning function.
      assert.match(run().stdout, /added .* to PATH/);
      assert.ok(readFileSync(rc).equals(expected),
        'the mentioning function is byte-for-byte unchanged and the managed block is appended');
      assert.ok(readFileSync(rc).includes(Buffer.from('\t# phantom-secrets PATH\n')),
        'the in-body mention survives the update');

      assert.match(run().stdout, /already wired into/);
      assert.ok(readFileSync(rc).equals(expected), 'the in-body mention is never rewritten');
    });
  }

  test(`${file} keeps an unrelated bash function identical in definition and behavior after the update`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-fneval-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const home = join(root, 'home');
    const bin = join(root, 'live', 'bin');
    const rc = shells.bash.rc(home);
    mkdirSync(home, { recursive: true });
    mkdirSync(bin, { recursive: true });
    writeFileSync(rc,
      'export PATH="/opt/user/bin:$PATH"\n'
      + 'greet() {\n\tprintf \'hello %s\\n\' "$1"\n}\n'
      + 'function deploy {\n\tprintf \'deployed %s\\n\' "$1"\n}\n',
      { mode: 0o600 });

    // Source the startup file in a clean bash and print each function's
    // declared definition plus one invocation. Byte-identical output before
    // and after proves the functions are unchanged in the only way a caller
    // can observe, while the trailing PATH check confirms the update applied.
    const probe = (pathCheck) => {
      const p = spawnSync('/bin/bash', [
        '--noprofile', '--norc', '-c',
        '. "$1" && declare -f greet && declare -f deploy && greet world && deploy api && ' + pathCheck,
        'path-test', rc,
      ], {
        encoding: 'utf8',
        timeout: 30000,
        env: { HOME: home, PATH: '/usr/bin:/bin' },
      });
      assert.ifError(p.error);
      return p;
    };

    const before = probe('[[ "$PATH" == "/opt/user/bin:/usr/bin:/bin" ]]');
    assert.equal(before.status, 0, before.stderr);
    assert.match(before.stdout, /hello world/);
    assert.match(before.stdout, /deployed api/);

    const updated = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
      encoding: 'utf8',
      timeout: 30000,
      env: { HOME: home, SHELL: '/bin/bash', PATH: '/usr/bin:/bin' },
    });
    assert.ifError(updated.error);
    assert.equal(updated.status, 0, updated.stderr);
    assert.match(updated.stdout, /added .* to PATH/);

    const after = probe(`[[ "$PATH" == "${bin}:/opt/user/bin:/usr/bin:/bin" ]]`);
    assert.equal(after.status, 0, after.stderr);
    assert.equal(after.stdout, before.stdout,
      'both function definitions and their observable output are identical before and after the PATH update');
  });
}
