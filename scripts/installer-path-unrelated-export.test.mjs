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
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';

// When the installer adds Phantom's bin dir to a startup file that has no
// Phantom block yet, every byte already in the file must survive, including an
// unrelated export that looks a lot like the PATH line. The update may only
// append the marker and PATH lines after the original bytes. The shipped text
// of add_to_user_path is extracted and run, as in the sibling PATH tests.
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
    exportLine: 'export   GREETING=\'héllo  "world" $HOME\'\t# keep me',
    mention: 'export PATH_NOTE="wired by # phantom-secrets PATH below"',
    mentionComment: '# remembers the # phantom-secrets PATH marker',
  },
  zsh: {
    shell: '/bin/zsh',
    rc: (h) => join(h, '.zshrc'),
    line: (p) => `export PATH="${p}:$PATH"`,
    exportLine: 'export   GREETING=\'héllo  "world" $HOME\'\t# keep me',
    mention: 'export PATH_NOTE="wired by # phantom-secrets PATH below"',
    mentionComment: '# remembers the # phantom-secrets PATH marker',
  },
  fish: {
    shell: '/usr/bin/fish',
    rc: (h) => join(h, '.config', 'fish', 'config.fish'),
    line: (p) => `set -gx PATH "${p}" $PATH`,
    exportLine: 'set -gx GREETING \'héllo  "world" $HOME\'',
    mention: 'set -g PATH_NOTE "wired by # phantom-secrets PATH below"',
    mentionComment: '# remembers the # phantom-secrets PATH marker',
  },
};

// Unrelated export: odd spacing, quotes, a dollar sign, a tab and non-ASCII.
const unrelatedExport = shells.bash.exportLine;

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

// Final-line endings the original file may have: the export must survive each.
const endings = { 'final newline': '\n', 'no final newline': '', 'CRLF final line': '\r\n' };

for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  for (const [name, config] of Object.entries(shells)) {
   for (const [ending, tail] of Object.entries(endings)) {
    test(`${file} keeps an unrelated export byte-for-byte when updating a ${name} PATH (${ending})`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-unrelated-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      const rc = config.rc(home);
      mkdirSync(dirname(rc), { recursive: true });
      mkdirSync(bin, { recursive: true });

      const original = Buffer.from(`# user config\n${unrelatedExport}\nexport PATH_NOTE=1${tail}`, 'utf8');
      writeFileSync(rc, original, { mode: 0o600 });

      const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
        encoding: 'utf8',
        timeout: 30000,
        env: { HOME: home, SHELL: config.shell, PATH: '/usr/bin:/bin' },
      });
      assert.ifError(result.error);
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, /added .* to PATH/);

      const after = readFileSync(rc);
      assert.ok(after.subarray(0, original.length).equals(original), 'original bytes are an unchanged prefix');
      assert.equal(
        after.subarray(original.length).toString('utf8'),
        `\n${marker}\n${config.line(bin)}\n`,
        'only the marker and PATH lines are appended',
      );
      assert.ok(after.toString('utf8').split('\n').includes(unrelatedExport), 'the unrelated export line is intact');
    });
   }
  }
}

// An export or comment that merely mentions the marker text is not a managed
// PATH block: only a line that is exactly the marker proves the installer has
// already run. The update must still append its block while the mentioning
// lines survive byte-for-byte, and a repeat update then short-circuits on the
// real marker line without touching the file.
for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  for (const [name, config] of Object.entries(shells)) {
    test(`${file} wires PATH past an unrelated ${name} export that mentions the marker`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-mention-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      const rc = config.rc(home);
      mkdirSync(dirname(rc), { recursive: true });
      mkdirSync(bin, { recursive: true });

      const original = Buffer.from(
        `# user config\n${config.exportLine}\n${config.mention}\n${config.mentionComment}\n`,
        'utf8',
      );
      writeFileSync(rc, original, { mode: 0o600 });

      const result = runUpdate(harness, config, home, bin);
      assert.match(result.stdout, /added .* to PATH/);

      const after = readFileSync(rc);
      assert.ok(after.subarray(0, original.length).equals(original),
        'the mentioning lines are an unchanged prefix');
      assert.equal(after.subarray(original.length).toString('utf8'),
        `\n${marker}\n${config.line(bin)}\n`,
        'only the marker and PATH lines are appended');
      const lines = after.toString('utf8').split('\n');
      assert.equal(lines.filter((l) => l === marker).length, 1,
        'exactly one real marker line after the update');
      assert.ok(lines.includes(config.mention), 'the mentioning export is intact');

      const second = runUpdate(harness, config, home, bin);
      assert.match(second.stdout, /already wired into/);
      assert.equal(readFileSync(rc).equals(after), true,
        'the repeat update leaves the file byte-for-byte unchanged');
    });
  }
}

// When the managed block is already present the update is a no-op, and an
// unrelated export keeps its bytes whether it sits before the block or was
// appended below it by the user after the installer ran.
for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  for (const [name, config] of Object.entries(shells)) {
    for (const position of ['before', 'after']) {
      test(`${file} keeps an unrelated ${name} export ${position} an already-wired block byte-for-byte`, (t) => {
        const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-wired-export-')));
        t.after(() => rmSync(root, { recursive: true, force: true }));
        const home = join(root, 'home');
        const bin = join(root, 'live', 'bin');
        const rc = config.rc(home);
        mkdirSync(dirname(rc), { recursive: true });
        mkdirSync(bin, { recursive: true });

        const block = `\n${marker}\n${config.line(bin)}\n`;
        const original = Buffer.from(position === 'before'
          ? `# user config\n${config.exportLine}\n${block}`
          : `# user config\n${block}${config.exportLine}\n`, 'utf8');
        writeFileSync(rc, original, { mode: 0o600 });

        const result = runUpdate(harness, config, home, bin);
        assert.match(result.stdout, /already wired into/);
        assert.doesNotMatch(result.stdout, /added .* to PATH/);
        assert.ok(readFileSync(rc).equals(original),
          'the already-wired startup file is byte-for-byte unchanged');
        assert.ok(readFileSync(rc, 'utf8').split('\n').includes(config.exportLine),
          'the unrelated export is intact');
      });
    }
  }
}

// End to end: a full installer run against an isolated HOME whose startup
// file already holds the unrelated export. The real call site — the PATH
// membership check, the install lock, staging, promotion and
// add_to_user_path — must leave the export an unchanged byte prefix.
for (const [file, installer] of Object.entries(copies)) {
  for (const [name, config] of Object.entries(shells)) {
    test(`${file} full install keeps an unrelated ${name} export as an unchanged prefix`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-export-full-')));
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

      const original = Buffer.from(`# user config\n${config.exportLine}\n`, 'utf8');
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
      assert.ok(after.subarray(0, original.length).equals(original),
        'the unrelated export is an unchanged prefix after the full install');
      assert.equal(after.subarray(original.length).toString('utf8'),
        `\n${marker}\n${config.line(install)}\n`,
        'the full install appends only the marker and PATH lines');
      assert.ok(after.toString('utf8').split('\n').includes(config.exportLine),
        'the unrelated export line is intact');
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

import "./installer-path-shell-export.test.mjs";
