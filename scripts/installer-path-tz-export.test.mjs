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

// `export TZ` is the timezone pin users put in shell startup files, and it
// must survive the installer's PATH update byte-for-byte: same bytes, same
// offset, exactly one occurrence, every surrounding byte an unchanged prefix,
// and only the managed marker block appended. The shipped text of
// add_to_user_path is extracted from both installer copies and run, as in the
// sibling PATH tests. Coverage spans bash, zsh, and fish startup files;
// TZ values that are plain, quoted, odd-spaced, dollar-referencing, POSIX
// rule strings, colon-prefixed zone paths, or that mention PATH or the
// marker text; TZ lookalike lines beside the export; a file whose only line
// is the export; an already-wired file the update must not rewrite; the full
// offline installer run; and a source check proving the preserved line still
// evaluates.
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
    tz: "export TZ='America/New_York'  # keep timezone",
    variants: [
      'export TZ=America/New_York',
      'export TZ=Etc/UTC',
      "export TZ='Europe/London'",
      'export   TZ=Asia/Tokyo   # force timezone',
      'export TZ="${SYSTEM_TZ:-UTC}"',
      'export TZ=EST5EDT,M3.2.0/2,M11.1.0',
      'export TZ=:/etc/localtime',
      'export TZ=UTC0 # remembered PATH order below',
      'export TZ="# phantom-secrets PATH"',
    ],
    tzBlock: [
      '# export TZ=UTC',
      "export TZ='America/New_York'",
      'export TZDIR=/usr/share/zoneinfo',
      'TZ=Etc/UTC',
    ],
  },
  zsh: {
    shell: '/bin/zsh',
    rc: (h) => join(h, '.zshrc'),
    line: (p) => `export PATH="${p}:$PATH"`,
    tz: "export TZ='America/New_York'  # keep timezone",
    variants: [
      'export TZ=America/New_York',
      'export TZ=Etc/UTC',
      "export TZ='Europe/London'",
      'export   TZ=Asia/Tokyo   # force timezone',
      'export TZ="${SYSTEM_TZ:-UTC}"',
      'export TZ=EST5EDT,M3.2.0/2,M11.1.0',
      'export TZ=:/etc/localtime',
      'export TZ=UTC0 # remembered PATH order below',
      'export TZ="# phantom-secrets PATH"',
    ],
    tzBlock: [
      '# export TZ=UTC',
      "export TZ='America/New_York'",
      'export TZDIR=/usr/share/zoneinfo',
      'TZ=Etc/UTC',
    ],
  },
  fish: {
    shell: '/usr/bin/fish',
    rc: (h) => join(h, '.config', 'fish', 'config.fish'),
    line: (p) => `set -gx PATH "${p}" $PATH`,
    tz: "export TZ='America/New_York'  # keep timezone",
    variants: [
      'set -gx TZ America/New_York',
      'set -gx TZ UTC',
      'set -gx TZ "UTC # phantom-secrets PATH"',
      // A bashism pasted into config.fish is still the user's line; the
      // update appends fish syntax and must leave it alone.
      'export TZ=Europe/Berlin',
    ],
    tzBlock: [
      '# set -gx TZ UTC',
      'set -gx TZ America/New_York',
      "export TZ='America/New_York'",
      'set -gx TZDIR /usr/share/zoneinfo',
    ],
  },
};

function runUpdate(harness, config, home, bin) {
  const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
    encoding: 'utf8',
    timeout: 30000,
    env: { HOME: home, SHELL: config.shell, PATH: '/usr/bin:/bin' },
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  return result;
}

// The TZ line must keep its bytes, its byte offset, and its count.
function assertLineIntact(after, before, tz) {
  const needle = Buffer.from(tz, 'utf8');
  const offset = before.indexOf(needle);
  assert.ok(offset >= 0, `fixture must contain ${JSON.stringify(tz)}`);
  assert.equal(after.indexOf(needle), offset,
    `${JSON.stringify(tz)} keeps its byte offset`);
  assert.equal(after.indexOf(needle, offset + 1), -1,
    `${JSON.stringify(tz)} appears exactly once`);
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

// The TZ line is the last line of its startup file for each leg, so every
// supported final-line ending exercises it: a newline, none at all, or CRLF
// whose carriage return is part of the preserved bytes.
const endings = { 'final newline': '\n', 'no final newline': '', 'CRLF final line': '\r\n' };

for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  for (const [name, config] of Object.entries(shells)) {
    for (const [ending, tail] of Object.entries(endings)) {
      test(`${file} keeps the ${name} TZ line byte-for-byte (${ending})`, (t) => {
        const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-tz-')));
        t.after(() => rmSync(root, { recursive: true, force: true }));
        const home = join(root, 'home');
        const bin = join(root, 'live', 'bin');
        const rc = config.rc(home);
        mkdirSync(dirname(rc), { recursive: true });
        mkdirSync(bin, { recursive: true });

        const original = Buffer.from(
          `# user config\nexport PATH_NOTE=1\n${config.tz}${tail}`, 'utf8');
        writeFileSync(rc, original, { mode: 0o600 });

        const result = runUpdate(harness, config, home, bin);
        assert.match(result.stdout, /added .* to PATH/);

        const after = readFileSync(rc);
        assertAppendedBlock(after, original, config, bin);
        assertLineIntact(after, original, config.tz);
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

// Every realistic TZ spelling shares one startup file here, including a
// comment that mentions PATH and a value that contains the marker text
// itself: the line-exact marker check must still run the update, and each
// variant must keep its bytes. A repeat update then short-circuits without a
// rewrite.
for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  for (const [name, config] of Object.entries(shells)) {
    test(`${file} keeps every ${name} TZ variant byte-for-byte`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-tz-variants-')));
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
      for (const tz of config.variants) assertLineIntact(after, original, tz);

      const second = runUpdate(harness, config, home, bin);
      assert.match(second.stdout, /already wired into/);
      assert.ok(readFileSync(rc).equals(after),
        'the repeat update leaves the file byte-for-byte unchanged');
    });
  }
}

// A real startup file parks TZ next to lookalikes: a commented-out twin, a
// related TZDIR export, and a bare TZ assignment. The update must leave every
// one of them — not just the export — untouched.
for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  for (const [name, config] of Object.entries(shells)) {
    test(`${file} keeps the ${name} TZ line inside a lookalike block byte-for-byte`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-tz-block-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      const rc = config.rc(home);
      mkdirSync(dirname(rc), { recursive: true });
      mkdirSync(bin, { recursive: true });

      const original = Buffer.from(
        `# user config\n${config.tzBlock.join('\n')}\n`, 'utf8');
      writeFileSync(rc, original, { mode: 0o600 });

      const result = runUpdate(harness, config, home, bin);
      assert.match(result.stdout, /added .* to PATH/);

      const after = readFileSync(rc);
      assertAppendedBlock(after, original, config, bin);
      for (const line of config.tzBlock) assertLineIntact(after, original, line);
    });
  }
}

// When the managed block already exists the update is a no-op; a TZ line
// keeps its bytes whether it sits above the block or below it.
for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  for (const [name, config] of Object.entries(shells)) {
    for (const position of ['before', 'after']) {
      test(`${file} keeps the ${name} TZ line ${position} an already-wired block byte-for-byte`, (t) => {
        const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-tz-wired-')));
        t.after(() => rmSync(root, { recursive: true, force: true }));
        const home = join(root, 'home');
        const bin = join(root, 'live', 'bin');
        const rc = config.rc(home);
        mkdirSync(dirname(rc), { recursive: true });
        mkdirSync(bin, { recursive: true });

        const block = `\n${marker}\n${config.line(bin)}\n`;
        const original = Buffer.from(position === 'before'
          ? `# user config\n${config.tz}\n${block}`
          : `# user config\n${block}${config.tz}\n`, 'utf8');
        writeFileSync(rc, original, { mode: 0o600 });

        const result = runUpdate(harness, config, home, bin);
        assert.match(result.stdout, /already wired into/);
        assert.doesNotMatch(result.stdout, /added .* to PATH/);
        assert.ok(readFileSync(rc).equals(original),
          'the already-wired startup file is byte-for-byte unchanged');
        assertLineIntact(readFileSync(rc), original, config.tz);
      });
    }
  }
}

// A startup file whose only content is the TZ line — no trailing newline —
// is the smallest file the update can touch.
for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  for (const [name, config] of Object.entries(shells)) {
    test(`${file} keeps a sole ${name} TZ line byte-for-byte`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-tz-sole-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      const rc = config.rc(home);
      mkdirSync(dirname(rc), { recursive: true });
      mkdirSync(bin, { recursive: true });

      const original = Buffer.from(config.tz, 'utf8');
      writeFileSync(rc, original, { mode: 0o600 });

      const result = runUpdate(harness, config, home, bin);
      assert.match(result.stdout, /added .* to PATH/);

      const after = readFileSync(rc);
      assertAppendedBlock(after, original, config, bin);
      assertLineIntact(after, original, config.tz);
    });
  }
}

// End to end: a full installer run against an isolated HOME whose startup
// file already holds the TZ line. The real call site — the PATH
// membership check, the install lock, staging, promotion, and
// add_to_user_path — must leave the line an unchanged byte prefix.
for (const [file, installer] of Object.entries(copies)) {
  for (const [name, config] of Object.entries(shells)) {
    test(`${file} full install keeps the ${name} TZ line byte-for-byte`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-tz-full-')));
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

      const original = Buffer.from(`# user config\n${config.tz}\n`, 'utf8');
      writeFileSync(rc, original, { mode: 0o600 });

      const result = spawnSync('/bin/bash', [installer], {
        encoding: 'utf8',
        timeout: 30000,
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
      assertLineIntact(after, original, config.tz);
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
  test(`${file} keeps TZ live when the updated bashrc is sourced`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-tz-eval-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const home = join(root, 'home');
    const bin = join(root, 'live', 'bin');
    const rc = shells.bash.rc(home);
    mkdirSync(home, { recursive: true });
    mkdirSync(bin, { recursive: true });
    writeFileSync(rc, `# user config\n${shells.bash.tz}\n`, { mode: 0o600 });

    const result = runUpdate(harness, shells.bash, home, bin);
    assert.match(result.stdout, /added .* to PATH/);

    const check = spawnSync('/bin/bash', [
      '--noprofile', '--norc', '-c',
      '. "$HOME/.bashrc" && [[ "$TZ" == \'America/New_York\' ]] && [[ "$PATH" == "$1:"* ]]',
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

// Same live check for zsh: the preserved TZ line must still evaluate and the
// new PATH entry must lead PATH when the updated .zshrc is sourced.
for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  test(`${file} keeps TZ live when the updated zshrc is sourced`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-tz-zsh-eval-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const home = join(root, 'home');
    const bin = join(root, 'live', 'bin');
    const rc = shells.zsh.rc(home);
    mkdirSync(home, { recursive: true });
    mkdirSync(bin, { recursive: true });
    writeFileSync(rc, `# user config\n${shells.zsh.tz}\n`, { mode: 0o600 });

    const result = runUpdate(harness, shells.zsh, home, bin);
    assert.match(result.stdout, /added .* to PATH/);

    const check = spawnSync('/bin/zsh', [
      '-f', '-c',
      '. "$HOME/.zshrc" && [[ "$TZ" == "America/New_York" ]] && [[ "$PATH" == "$1:"* ]]',
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
