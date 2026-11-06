import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { pathUpdateHarness } from './lib/installer-path-harness.mjs';
import { fileURLToPath } from 'node:url';

// A hand-edited startup file can end in an unrelated line with no trailing
// newline: a stray fragment, a commented-out PATH entry, a near-miss copy of
// the managed marker, or even non-text bytes. The PATH update treats the file
// as opaque bytes — it copies it into a private candidate and appends
// '\n# phantom-secrets PATH\n<PATH line>\n' — so the last line's bytes must
// survive untouched and the appended '\n' must terminate it, never glue the
// managed block onto it. When the exact marker already occupies a whole line in the file
// the update is a no-op, so the whole file — unterminated tail included —
// comes back byte-for-byte. One end-to-end leg pins the call-site gate: when
// the install dir is already on PATH the startup file is never opened at all.
// installer-path-final-newline.test.mjs owns the plain unterminated-setting
// shapes and the full offline run; this file owns the unrelated-line edges.
const installers = {
  'scripts/install.sh': new URL('install.sh', import.meta.url),
  'apps/web/public/install.sh': new URL('../apps/web/public/install.sh', import.meta.url),
};

const shells = {
  bash: {
    shell: '/bin/bash',
    rc: (home) => join(home, '.bashrc'),
    line: (bin) => `export PATH="${bin}:$PATH"`,
  },
  zsh: {
    shell: '/bin/zsh',
    rc: (home) => join(home, '.zshrc'),
    line: (bin) => `export PATH="${bin}:$PATH"`,
  },
  fish: {
    shell: '/usr/bin/fish',
    rc: (home) => join(home, '.config', 'fish', 'config.fish'),
    line: (bin) => `set -gx PATH "${bin}" $PATH`,
  },
};

const marker = '# phantom-secrets PATH';

// add_to_user_path runs under `set -euo pipefail` in the installer and calls
// these helpers; extract the exact same text so the exercised code is the
// shipped code.
const harnessFor = pathUpdateHarness;

// spawnSync feeds the child a socketpair as stdin, and bash treats a socket
// on fd 0 as a remote-shell invocation: it sources ~/.bashrc before running
// the -c string. That would execute the very startup file under test — a
// PATH-replacing or command-shadowing line would corrupt the harness itself.
// 'ignore' gives the shell /dev/null instead, so the file under test stays
// opaque bytes to add_to_user_path, exactly as in a terminal install.
function runPathUpdate(harness, config, home, bin) {
  const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
    encoding: 'utf8',
    timeout: 30000,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { HOME: home, SHELL: config.shell, PATH: '/usr/bin:/bin' },
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  return result;
}

// Shapes are the exact bytes written to the startup file; every one lacks a
// final newline. A function body is evaluated per shell so a shape can reuse
// the installer's own PATH-line format.
const resolveShape = (shape, config, bin) => {
  const content = typeof shape === 'function' ? shape(config, bin) : shape;
  return {
    content,
    bytes: typeof content === 'string' ? Buffer.from(content, 'utf8') : content,
  };
};

// The marker is the only idempotence key, so none of these may contain the
// exact '# phantom-secrets PATH' whole line: every one must still get the
// managed block appended after the preserved tail.
const unterminatedUnrelated = [
  ['a dangling shell keyword', 'fi'],
  ['an unclosed quote', 'export MOTD="unclosed'],
  ['a commented-out PATH export', '# export PATH="/opt/legacy/bin:$PATH"'],
  ['a bare PATH assignment', 'PATH=/opt/legacy/bin'],
  ['a near-miss marker missing a word', '# phantom PATH'],
  ['a near-miss marker missing the space', '#phantom-secrets PATH'],
  ['a near-miss marker with a doubled space', '# phantom-secrets  PATH'],
  ['a differently-cased marker', '# Phantom-Secrets PATH'],
  ['a doubled-hash marker line', '## phantom-secrets PATH'],
  ['a marker with trailing text', '# phantom-secrets PATH v2 notes'],
  ['a marker inside a quoted setting', 'export NOTE="# phantom-secrets PATH"'],
  ['trailing whitespace', 'export EDITOR=vim \t '],
  ['a carriage-return tail', 'export EDITOR=vim\r'],
  ['a single character', 'x'],
  ['a very long line', `# ${'y'.repeat(8190)}`],
  ['non-UTF-8 bytes', Buffer.concat([
    Buffer.from('# cfg\nfoo', 'utf8'),
    Buffer.from([0xff, 0xfe, 0x00]),
    Buffer.from('bar', 'utf8'),
  ])],
  // A line byte-identical to what the installer writes, but written by hand:
  // without the marker it does not count as wired, and it still survives as
  // its own line ahead of the appended block.
  ['a hand-written copy of the managed PATH line', (config, bin) => config.line(bin)],
];

function assertNoTempFiles(rc) {
  assert.deepEqual(
    readdirSync(dirname(rc)).filter((name) => name.startsWith('.phantom-path.')),
    [],
    'no PATH-update temporary files remain beside the startup file',
  );
}

for (const [label, url] of Object.entries(installers)) {
  const harness = harnessFor(readFileSync(fileURLToPath(url), 'utf8'), label);
  for (const [shellName, config] of Object.entries(shells)) {
    for (const [shape, raw] of unterminatedUnrelated) {
      test(`${label} preserves an unterminated ${shellName} line with ${shape}`, (t) => {
        const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-unrelated-')));
        t.after(() => rmSync(root, { recursive: true, force: true }));
        const home = join(root, 'home');
        const bin = join(root, 'live', 'bin');
        const rc = config.rc(home);
        mkdirSync(dirname(rc), { recursive: true });
        mkdirSync(bin, { recursive: true });
        const { content, bytes } = resolveShape(raw, config, bin);
        writeFileSync(rc, bytes, { mode: 0o600 });

        const result = runPathUpdate(harness, config, home, bin);
        assert.match(result.stdout, /added .* to PATH/);

        const updated = readFileSync(rc);
        assert.ok(updated.subarray(0, bytes.length).equals(bytes),
          'every pre-existing byte, including the unrelated last line, is intact');
        assert.equal(updated[bytes.length], 0x0a,
          'the unrelated last line is terminated, not glued to the managed block');
        assert.equal(updated.subarray(bytes.length).toString('utf8'),
          `\n${marker}\n${config.line(bin)}\n`,
          'only the managed block is appended after the preserved line');
        if (typeof content === 'string') {
          const lastLine = content.slice(content.lastIndexOf('\n') + 1);
          assert.ok(updated.toString('utf8').split('\n').includes(lastLine),
            'the unrelated last line survives as its own line');
        }
        assert.equal(statSync(rc).mode & 0o777, 0o600,
          'startup file mode is preserved');
        assertNoTempFiles(rc);
      });
    }

    // An exact whole-line marker short-circuits the update, so the unterminated tail
    // is preserved in the strongest way: the file is never rewritten.
    const markerBearing = [
      ['a managed block followed by an unrelated tail',
        `# cfg\n${marker}\nexport PATH="/old/bin:$PATH"\nunrelated-tail`],
    ];
    for (const [shape, text] of markerBearing) {
      test(`${label} leaves a ${shellName} file byte-for-byte when ${shape} ends it`, (t) => {
        const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-marked-')));
        t.after(() => rmSync(root, { recursive: true, force: true }));
        const home = join(root, 'home');
        const bin = join(root, 'live', 'bin');
        const rc = config.rc(home);
        mkdirSync(dirname(rc), { recursive: true });
        mkdirSync(bin, { recursive: true });
        writeFileSync(rc, text, { mode: 0o600 });

        const result = runPathUpdate(harness, config, home, bin);
        assert.match(result.stdout, /already wired into/);
        assert.doesNotMatch(result.stdout, /added .* to PATH/,
          'a marker-bearing file must not gain a second PATH block');
        assert.equal(readFileSync(rc, 'utf8'), text,
          'the whole file, unterminated tail included, is byte-for-byte unchanged');
        assert.equal(statSync(rc).mode & 0o777, 0o600,
          'startup file mode is preserved');
        assertNoTempFiles(rc);
      });
    }
  }
}

// End-to-end through the real installer: when the install dir is already on
// PATH the call-site gate skips add_to_user_path entirely, so an existing
// startup file ending in an unrelated unterminated line is not even opened.
// This complements installer-path-final-newline.test.mjs, which runs the same
// offline install with the update taking the append path.
for (const [label, url] of Object.entries(installers)) {
  test(`${label} leaves an unterminated .bashrc untouched when the install dir is already on PATH`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-skipped-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const fixture = join(root, 'fixture');
    const payload = join(root, 'payload');
    const home = join(root, 'home');
    const install = join(root, 'live', 'bin');
    for (const dir of [fixture, payload, home]) mkdirSync(dir, { recursive: true });
    for (const name of ['phantom', 'phantom-mcp']) {
      writeFileSync(join(payload, name), `#!/bin/sh\necho "${name} 1.2.3"\n`);
      chmodSync(join(payload, name), 0o755);
    }
    const os = { darwin: 'apple-darwin', linux: 'unknown-linux-gnu' }[process.platform];
    const arch = { x64: 'x86_64', arm64: 'aarch64' }[process.arch];
    assert.ok(os && arch, 'test requires a supported Unix installer target');
    const archive = `phantom-${arch}-${os}.tar.gz`;
    execFileSync('/usr/bin/tar', ['-czf', join(fixture, archive), '-C', payload, 'phantom', 'phantom-mcp']);
    const digest = createHash('sha256').update(readFileSync(join(fixture, archive))).digest('hex');
    writeFileSync(join(fixture, `${archive}.sha256`), `${digest}  ${archive}\n`);

    const rc = join(home, '.bashrc');
    const original = '# user shell config\nexport EDITOR=vim';
    writeFileSync(rc, original, { mode: 0o600 });

    const env = { ...process.env };
    for (const name of ['PHANTOM_REPO', 'PHANTOM_TEST_FAIL_AFTER_PROMOTION',
      'PHANTOM_INSTALL_LOCK_WAIT_SECONDS', 'PHANTOM_INSTALL_LOCK_STALE_SECONDS',
      'PHANTOM_INSTALL_LOCK_HEARTBEAT_SECONDS']) delete env[name];
    const result = spawnSync('/bin/bash', [fileURLToPath(url)], {
      encoding: 'utf8',
      timeout: 30000,
      // /dev/null stdin: a socketpair would make bash source the very .bashrc
      // under test before running the installer (see runPathUpdate).
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {
        ...env,
        HOME: home,
        SHELL: '/bin/bash',
        PATH: `${install}:${env.PATH}`,
        PHANTOM_INSTALL_DIR: install,
        PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
        PHANTOM_TEST_LOCAL_RELEASE_DIR: fixture,
        PHANTOM_TAG: 'v1.2.3',
      },
    });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /done\. phantom 1\.2\.3/);
    assert.doesNotMatch(result.stdout, /added .* to PATH|already wired into/,
      'the PATH update never runs when the install dir is already on PATH');
    assert.equal(readFileSync(rc, 'utf8'), original,
      'the unterminated startup file is byte-for-byte untouched');
    assertNoTempFiles(rc);
  });
}
