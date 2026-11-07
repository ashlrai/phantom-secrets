import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
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

// `export SHELL` is the login-shell pin users put in shell startup files,
// and it must survive the installer's PATH update byte-for-byte: same bytes,
// same offset, exactly one occurrence, every surrounding byte an unchanged
// prefix, and only the managed marker block appended. The installer picks
// the startup file from the SHELL environment variable, never from a SHELL
// claim inside a file, so the preserved line may even name a different
// shell than the file it sits in. The shipped text of add_to_user_path is
// extracted from both installer copies and run, as in the sibling PATH
// tests. Coverage spans bash, zsh, and fish startup files; SHELL values
// that are plain, quoted, odd-spaced, dollar- or command-referencing, or
// that mention PATH or the marker text; SHELL lookalike lines beside the
// export; a file whose only line is the export; an already-wired file the
// update must not rewrite; a decoy startup file whose own SHELL claim
// cannot redirect the update; the full offline installer run; and a source
// check proving the preserved line still evaluates.
const copies = {
  'scripts/install.sh': resolve(import.meta.dirname, 'install.sh'),
  'apps/web/public/install.sh': resolve(import.meta.dirname, '..', 'apps', 'web', 'public', 'install.sh'),
};

function extractFunction(source, name, file) {
  const start = source.indexOf(`${name}()`);
  assert.ok(start >= 0, `${file}: locate ${name}`);
  const lineEnd = source.indexOf('\n', start);
  if (source.slice(start, lineEnd).trimEnd().endsWith('}')) {
    return source.slice(start, lineEnd + 1);
  }
  const end = source.indexOf('\n}\n', start);
  assert.ok(end > start, `${file}: locate end of ${name}`);
  return source.slice(start, end + '\n}\n'.length);
}

const harnessFor = (source, file) => ['set -euo pipefail', 'umask 077',
  ...['say', 'file_identity', 'file_link_count', 'add_to_user_path']
    .map((name) => extractFunction(source, name, file)),
  'add_to_user_path "$1"',
].join('\n');

const marker = '# phantom-secrets PATH';
const shells = {
  bash: {
    shell: '/bin/bash',
    rc: (h) => join(h, '.bashrc'),
    line: (p) => `export PATH="${p}:$PATH"`,
    shellLine: 'export SHELL=/bin/zsh  # login shell',
    variants: [
      'export SHELL=/bin/zsh',
      'export SHELL=/usr/local/bin/fish',
      "export SHELL='/bin/bash'",
      'export   SHELL=/opt/homebrew/bin/zsh   # login shell',
      'export SHELL="$(command -v zsh)"',
      'export SHELL="$HOME/bin/nu"',
      'export SHELL=/bin/sh # remembered PATH order below',
      'export SHELL="# phantom-secrets PATH"',
    ],
    shellBlock: [
      '# export SHELL=/bin/tcsh',
      'export SHELL=/bin/zsh',
      'export SHELL_SESSION_HISTORY=0',
      'SHELL=/bin/sh',
    ],
  },
  zsh: {
    shell: '/bin/zsh',
    rc: (h) => join(h, '.zshrc'),
    line: (p) => `export PATH="${p}:$PATH"`,
    shellLine: 'export SHELL=/bin/zsh  # login shell',
    variants: [
      'export SHELL=/bin/zsh',
      'export SHELL=/usr/local/bin/fish',
      "export SHELL='/bin/bash'",
      'export   SHELL=/opt/homebrew/bin/zsh   # login shell',
      'export SHELL="$(command -v zsh)"',
      'export SHELL="$HOME/bin/nu"',
      'export SHELL=/bin/sh # remembered PATH order below',
      'export SHELL="# phantom-secrets PATH"',
    ],
    shellBlock: [
      '# export SHELL=/bin/tcsh',
      'export SHELL=/bin/zsh',
      'export SHELL_SESSION_HISTORY=0',
      'SHELL=/bin/sh',
    ],
  },
  fish: {
    shell: '/usr/bin/fish',
    rc: (h) => join(h, '.config', 'fish', 'config.fish'),
    line: (p) => `set -gx PATH "${p}" $PATH`,
    shellLine: 'export SHELL=/bin/zsh  # login shell',
    variants: [
      'set -gx SHELL /usr/bin/fish',
      'set -gx SHELL /bin/zsh',
      'set -gx SHELL "/bin/zsh # phantom-secrets PATH"',
      // A bashism pasted into config.fish is still the user's line; the
      // update appends fish syntax and must leave it alone.
      'export SHELL=/bin/zsh',
    ],
    shellBlock: [
      '# set -gx SHELL /bin/zsh',
      'set -gx SHELL /usr/bin/fish',
      "export SHELL='/bin/zsh'",
      'set -gx SHELL_SESSION_HISTORY 0',
    ],
  },
};

// Non-socket stdin is load-bearing here, not a nicety: node's stdio pipes
// are socketpairs on macOS, and bash reads ~/.bashrc when its stdin is a
// socket (the remote-shell-daemon heuristic), even for -c. Every fixture
// below parks an `export SHELL` line in the startup file, and that line is
// not inert like a TZ or LANG export — sourcing it rewrites the very SHELL
// the update reads to choose the file, and the appended PATH block lands
// in the wrong rc. A closed stdin keeps the shipped code the only actor.
const harnessStdio = ['ignore', 'pipe', 'pipe'];

function runUpdate(harness, config, home, bin) {
  const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
    encoding: 'utf8',
    timeout: 30000,
    stdio: harnessStdio,
    env: { HOME: home, SHELL: config.shell, PATH: '/usr/bin:/bin' },
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  return result;
}

// The SHELL line must keep its bytes, its byte offset, and its count.
function assertLineIntact(after, before, shellLine) {
  const needle = Buffer.from(shellLine, 'utf8');
  const offset = before.indexOf(needle);
  assert.ok(offset >= 0, `fixture must contain ${JSON.stringify(shellLine)}`);
  assert.equal(after.indexOf(needle), offset,
    `${JSON.stringify(shellLine)} keeps its byte offset`);
  assert.equal(after.indexOf(needle, offset + 1), -1,
    `${JSON.stringify(shellLine)} appears exactly once`);
}

function assertAppendedBlock(after, original, config, bin) {
  assert.ok(after.subarray(0, original.length).equals(original),
    'the startup file keeps its original bytes as an unchanged prefix');
  assert.equal(
    after.subarray(original.length).toString('utf8'),
    `\n${marker}\n${config.line(bin)}\n`,
    'only the marker and PATH lines are appended',
  );
}

// The SHELL line is the last line of its startup file for each leg, so every
// supported final-line ending exercises it: a newline, none at all, or CRLF
// whose carriage return is part of the preserved bytes.
const endings = { 'final newline': '\n', 'no final newline': '', 'CRLF final line': '\r\n' };

for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  for (const [name, config] of Object.entries(shells)) {
    for (const [ending, tail] of Object.entries(endings)) {
      test(`${file} keeps the ${name} SHELL line byte-for-byte (${ending})`, (t) => {
        const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-shell-')));
        t.after(() => rmSync(root, { recursive: true, force: true }));
        const home = join(root, 'home');
        const bin = join(root, 'live', 'bin');
        const rc = config.rc(home);
        mkdirSync(dirname(rc), { recursive: true });
        mkdirSync(bin, { recursive: true });

        const original = Buffer.from(
          `# user config\nexport PATH_NOTE=1\n${config.shellLine}${tail}`, 'utf8');
        writeFileSync(rc, original, { mode: 0o600 });

        const result = runUpdate(harness, config, home, bin);
        assert.match(result.stdout, /added .* to PATH/);

        const after = readFileSync(rc);
        assertAppendedBlock(after, original, config, bin);
        assertLineIntact(after, original, config.shellLine);
        assert.equal(statSync(rc).mode & 0o777, 0o600,
          'the startup file keeps its permissions');
        assert.deepEqual(
          readdirSync(dirname(rc)).filter((n) => n.startsWith('.phantom-path.')),
          [],
          'no PATH-update temporary files remain beside the startup file',
        );
      });
    }
  }
}

// Every realistic SHELL spelling shares one startup file here, including a
// comment that mentions PATH and a value that contains the marker text
// itself: the line-exact marker check must still run the update, and each
// variant must keep its bytes. A repeat update then short-circuits without a
// rewrite.
for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  for (const [name, config] of Object.entries(shells)) {
    test(`${file} keeps every ${name} SHELL variant byte-for-byte`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-shell-variants-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      const rc = config.rc(home);
      mkdirSync(dirname(rc), { recursive: true });
      mkdirSync(bin, { recursive: true });

      const original = Buffer.from(
        `# user config\n${config.variants.join('\n')}\n`, 'utf8');
      writeFileSync(rc, original, { mode: 0o600 });

      const result = runUpdate(harness, config, home, bin);
      assert.match(result.stdout, /added .* to PATH/);

      const after = readFileSync(rc);
      assertAppendedBlock(after, original, config, bin);
      for (const shellLine of config.variants) assertLineIntact(after, original, shellLine);

      const second = runUpdate(harness, config, home, bin);
      assert.match(second.stdout, /already wired into/);
      assert.ok(readFileSync(rc).equals(after),
        'the repeat update leaves the file byte-for-byte unchanged');
    });
  }
}

// A real startup file parks SHELL next to lookalikes: a commented-out twin,
// a SHELL_SESSION_HISTORY export, and a bare SHELL assignment. The update
// must leave every one of them — not just the export — untouched.
for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  for (const [name, config] of Object.entries(shells)) {
    test(`${file} keeps the ${name} SHELL line inside a lookalike block byte-for-byte`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-shell-block-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      const rc = config.rc(home);
      mkdirSync(dirname(rc), { recursive: true });
      mkdirSync(bin, { recursive: true });

      const original = Buffer.from(
        `# user config\n${config.shellBlock.join('\n')}\n`, 'utf8');
      writeFileSync(rc, original, { mode: 0o600 });

      const result = runUpdate(harness, config, home, bin);
      assert.match(result.stdout, /added .* to PATH/);

      const after = readFileSync(rc);
      assertAppendedBlock(after, original, config, bin);
      for (const line of config.shellBlock) assertLineIntact(after, original, line);
    });
  }
}

// The update chooses its startup file from the SHELL environment variable,
// so a SHELL claim inside a file can name any shell — even the one a decoy
// file would belong to — without redirecting anything. Both files hold a
// SHELL line that disagrees with the env-selected file; only the selected
// file may gain the PATH block, and the decoy keeps every byte.
const decoys = [
  {
    envShell: '/usr/bin/fish',
    target: (h) => join(h, '.config', 'fish', 'config.fish'),
    targetLine: (p) => `set -gx PATH "${p}" $PATH`,
    targetContent: 'export SHELL=/bin/bash',
    decoy: (h) => join(h, '.zshrc'),
    decoyContent: '# user config\nexport SHELL=/bin/zsh\n',
  },
  {
    envShell: '/bin/bash',
    target: (h) => join(h, '.bashrc'),
    targetLine: (p) => `export PATH="${p}:$PATH"`,
    targetContent: 'export SHELL=/bin/zsh',
    decoy: (h) => join(h, '.config', 'fish', 'config.fish'),
    decoyContent: '# user config\nset -gx SHELL /usr/bin/fish\n',
  },
];
for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  for (const scenario of decoys) {
    test(`${file} updates only the ${scenario.envShell} file when a decoy claims SHELL`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-shell-decoy-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      const rc = scenario.target(home);
      const decoy = scenario.decoy(home);
      mkdirSync(dirname(rc), { recursive: true });
      mkdirSync(dirname(decoy), { recursive: true });
      mkdirSync(bin, { recursive: true });

      const original = Buffer.from(
        `# user config\n${scenario.targetContent}\n`, 'utf8');
      writeFileSync(rc, original, { mode: 0o600 });
      writeFileSync(decoy, scenario.decoyContent, { mode: 0o600 });

      const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
        encoding: 'utf8',
        timeout: 30000,
        stdio: harnessStdio,
        env: { HOME: home, SHELL: scenario.envShell, PATH: '/usr/bin:/bin' },
      });
      assert.ifError(result.error);
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, /added .* to PATH/);

      const after = readFileSync(rc);
      assert.ok(after.subarray(0, original.length).equals(original),
        'the env-selected file keeps its original bytes as an unchanged prefix');
      assert.equal(
        after.subarray(original.length).toString('utf8'),
        `\n${marker}\n${scenario.targetLine(bin)}\n`,
        'the selected file gains only its own shell dialect of PATH line',
      );
      assertLineIntact(after, original, scenario.targetContent);
      assert.equal(readFileSync(decoy, 'utf8'), scenario.decoyContent,
        'the decoy startup file is never read or rewritten');
    });
  }
}

// When the managed block already exists the update is a no-op; a SHELL line
// keeps its bytes whether it sits above the block or below it.
for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  for (const [name, config] of Object.entries(shells)) {
    for (const position of ['before', 'after']) {
      test(`${file} keeps the ${name} SHELL line ${position} an already-wired block byte-for-byte`, (t) => {
        const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-shell-wired-')));
        t.after(() => rmSync(root, { recursive: true, force: true }));
        const home = join(root, 'home');
        const bin = join(root, 'live', 'bin');
        const rc = config.rc(home);
        mkdirSync(dirname(rc), { recursive: true });
        mkdirSync(bin, { recursive: true });

        const block = `\n${marker}\n${config.line(bin)}\n`;
        const original = Buffer.from(position === 'before'
          ? `# user config\n${config.shellLine}\n${block}`
          : `# user config\n${block}${config.shellLine}\n`, 'utf8');
        writeFileSync(rc, original, { mode: 0o600 });

        const result = runUpdate(harness, config, home, bin);
        assert.match(result.stdout, /already wired into/);
        assert.doesNotMatch(result.stdout, /added .* to PATH/);
        assert.ok(readFileSync(rc).equals(original),
          'the already-wired startup file is byte-for-byte unchanged');
        assertLineIntact(readFileSync(rc), original, config.shellLine);
      });
    }
  }
}

// A startup file whose only content is the SHELL line — no trailing newline —
// is the smallest file the update can touch.
for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  for (const [name, config] of Object.entries(shells)) {
    test(`${file} keeps a sole ${name} SHELL line byte-for-byte`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-shell-sole-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      const rc = config.rc(home);
      mkdirSync(dirname(rc), { recursive: true });
      mkdirSync(bin, { recursive: true });

      const original = Buffer.from(config.shellLine, 'utf8');
      writeFileSync(rc, original, { mode: 0o600 });

      const result = runUpdate(harness, config, home, bin);
      assert.match(result.stdout, /added .* to PATH/);

      const after = readFileSync(rc);
      assertAppendedBlock(after, original, config, bin);
      assertLineIntact(after, original, config.shellLine);
    });
  }
}

// End to end: a full installer run against an isolated HOME whose startup
// file already holds the SHELL line. The real call site — the PATH
// membership check, the install lock, staging, promotion, and
// add_to_user_path — must leave the line an unchanged byte prefix.
for (const [file, installer] of Object.entries(copies)) {
  for (const [name, config] of Object.entries(shells)) {
    test(`${file} full install keeps the ${name} SHELL line byte-for-byte`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-shell-full-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const install = join(root, 'live', 'bin');
      const release = join(root, 'release');
      const payload = join(root, 'payload');
      const rc = config.rc(home);
      mkdirSync(dirname(rc), { recursive: true });
      mkdirSync(release, { recursive: true });
      mkdirSync(payload, { recursive: true });

      for (const binName of ['phantom', 'phantom-mcp']) {
        writeFileSync(join(payload, binName), `#!/bin/sh\nprintf '${binName} 1.2.3\\n'\n`, { mode: 0o755 });
      }
      const os = { darwin: 'apple-darwin', linux: 'unknown-linux-gnu' }[process.platform];
      const arch = { x64: 'x86_64', arm64: 'aarch64' }[process.arch];
      assert.ok(os && arch, 'supported Unix installer target required');
      const archive = `phantom-${arch}-${os}.tar.gz`;
      const archivePath = join(release, archive);
      execFileSync('tar', ['-czf', archivePath, '-C', payload, 'phantom', 'phantom-mcp']);
      const digest = createHash('sha256').update(readFileSync(archivePath)).digest('hex');
      writeFileSync(`${archivePath}.sha256`, `${digest}  ${archive}\n`);

      const original = Buffer.from(`# user config\n${config.shellLine}\n`, 'utf8');
      writeFileSync(rc, original, { mode: 0o600 });

      const result = spawnSync('/bin/bash', [installer], {
        encoding: 'utf8',
        timeout: 30000,
        stdio: harnessStdio,
        env: {
          HOME: home, SHELL: config.shell, PATH: '/usr/bin:/bin',
          PHANTOM_INSTALL_DIR: install, PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
          PHANTOM_TEST_LOCAL_RELEASE_DIR: release, PHANTOM_TAG: 'v1.2.3',
        },
      });
      assert.ifError(result.error);
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, /added .* to PATH/);

      const after = readFileSync(rc);
      assertAppendedBlock(after, original, config, install);
      assertLineIntact(after, original, config.shellLine);
      assert.deepEqual(
        readdirSync(dirname(rc)).filter((n) => n.startsWith('.phantom-path.')),
        [],
        'no PATH-update temporary files remain beside the startup file',
      );
      assert.deepEqual(readdirSync(join(root, 'live')), ['bin'],
        'no staging, backup, or lock leftovers beside the install dir');
      assert.deepEqual(readdirSync(install).sort(),
        ['.phantom-install-source.json', 'phantom', 'phantom-mcp'].sort(),
        'the install dir holds only the installed payload');
    });
  }
}

// Bytes are necessary but not sufficient: sourcing the updated .bashrc in a
// clean bash must still evaluate the preserved line to its original value.
for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  test(`${file} keeps SHELL live when the updated bashrc is sourced`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-shell-eval-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const home = join(root, 'home');
    const bin = join(root, 'live', 'bin');
    const rc = shells.bash.rc(home);
    mkdirSync(home, { recursive: true });
    mkdirSync(bin, { recursive: true });
    writeFileSync(rc, `# user config\n${shells.bash.shellLine}\n`, { mode: 0o600 });

    const result = runUpdate(harness, shells.bash, home, bin);
    assert.match(result.stdout, /added .* to PATH/);

    const check = spawnSync('/bin/bash', [
      '--noprofile', '--norc', '-c',
      '. "$HOME/.bashrc" && [[ "$SHELL" == \'/bin/zsh\' ]] && [[ "$PATH" == "$1:"* ]]',
      'path-test', bin,
    ], {
      encoding: 'utf8',
      timeout: 30000,
      stdio: harnessStdio,
      env: { HOME: home, PATH: '/usr/bin:/bin' },
    });
    assert.ifError(check.error);
    assert.equal(check.status, 0, check.stderr);
  });
}

test('standalone shell preservation check', () => {
  const result = spawnSync('bash', [resolve(import.meta.dirname, 'installer-path-shell.test.sh')], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 30000,
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
});
