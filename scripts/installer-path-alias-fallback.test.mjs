import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';

// Every other PATH-update test exports SHELL explicitly as /bin/bash,
// /bin/zsh, or /usr/bin/fish. This file covers the startup-file fallbacks in
// add_to_user_path: unset SHELL (the installer runs under bash, which assigns
// SHELL to the login shell at startup, so the update lands in the login
// shell's startup file — NOT always .bashrc), empty SHELL and unrecognized
// shells (the ${SHELL:-bash} default and the case catch-all both land in
// .bashrc), and pathless shell names (basename maps bare zsh and fish to
// their own startup files). Whichever file the fallback picks, an unrelated
// shell alias inside it must survive the update byte-for-byte, compared as
// raw Buffers, and every other shell's startup file must never even be read.
// A startup file holding the marker line but missing the PATH line already
// counts as wired for `grep -qxF`, so the run is a no-op and the alias — and
// the absent PATH line — stay exactly as they were. The last leg runs the
// complete offline install.sh with SHELL unset to prove the login-shell
// wiring end to end.
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
const bashAlias = Buffer.from('alias gs=\'git status -sb \\\n  && echo "done: $(date) `id -un`"\'\t  \r\n');
const zshAlias = Buffer.from('alias -g L=\'| less -R\' # café ✓\t \r\n');
const fishAlias = Buffer.from('alias gs "git status -sb; echo \\"$USER\\"" \t \r\n');

const posixLine = (b) => `export PATH="${b}:$PATH"`;
const fishLine = (b) => `set -gx PATH "${b}" $PATH`;

const bashRc = { rc: '.bashrc', alias: bashAlias, line: posixLine };
const startupFor = (shellName) => ({
  zsh: { rc: '.zshrc', alias: zshAlias, line: posixLine },
  fish: { rc: '.config/fish/config.fish', alias: fishAlias, line: fishLine },
}[shellName] || bashRc);

// Resolve the shell name exactly as add_to_user_path will: run its own
// `basename "${SHELL:-bash}"` under bash in the same environment. When SHELL
// is unset, bash assigns the login shell at startup; an empty value falls
// through to the bash default.
function resolveShell(env) {
  const probe = spawnSync('/usr/bin/env', [
    '-i', 'HOME=/nonexistent', 'PATH=/usr/bin:/bin',
    ...Object.entries(env).map(([key, value]) => `${key}=${value}`),
    '/bin/bash', '-c', 'basename "${SHELL:-bash}"',
  ], { encoding: 'utf8', timeout: 30000 });
  assert.ifError(probe.error);
  assert.equal(probe.status, 0, probe.stderr);
  return probe.stdout.trim();
}

// env holds the child's extra environment; SHELL omitted entirely means the
// variable is unset (env replaces the whole child environment). The startup
// file each case must resolve to is derived with resolveShell, so the legs
// stay correct whatever the login shell is.
const fallbacks = [
  { name: 'unset SHELL' },
  { name: 'empty SHELL', env: { SHELL: '' } },
  { name: 'sh', env: { SHELL: '/bin/sh' } },
  { name: 'dash', env: { SHELL: '/usr/bin/dash' } },
  { name: 'tcsh', env: { SHELL: '/bin/tcsh' } },
  { name: 'a pathless zsh', env: { SHELL: 'zsh' } },
  { name: 'a pathless fish', env: { SHELL: 'fish' } },
];

const siblingSeeds = {
  '.bashrc': Buffer.from('alias bw="echo bash sibling"\t \r\n'),
  '.zshrc': Buffer.from('alias zw="echo zsh sibling"\t \r\n'),
  '.config/fish/config.fish': Buffer.from('alias fw "echo fish sibling"\t \r\n'),
};

function makeFixture(root, os, arch) {
  const fixture = join(root, 'release');
  const payload = join(root, 'payload');
  mkdirSync(fixture, { recursive: true });
  mkdirSync(payload, { recursive: true });
  for (const name of ['phantom', 'phantom-mcp']) {
    writeFileSync(join(payload, name), `#!/bin/sh\necho "${name} 1.2.3"\n`);
    chmodSync(join(payload, name), 0o755);
  }
  const archive = `phantom-${arch}-${os}.tar.gz`;
  execFileSync('tar', ['-czf', join(fixture, archive), '-C', payload, 'phantom', 'phantom-mcp']);
  const digest = createHash('sha256').update(readFileSync(join(fixture, archive))).digest('hex');
  writeFileSync(join(fixture, `${archive}.sha256`), `${digest}  ${archive}\n`);
  return fixture;
}

const os = { darwin: 'apple-darwin', linux: 'unknown-linux-gnu' }[process.platform];
const arch = { x64: 'x86_64', arm64: 'aarch64' }[process.arch];

for (const [file, installer] of Object.entries(copies)) {
  const harness = harnessFor(readFileSync(installer, 'utf8'), file);
  for (const config of fallbacks) {
    test(`${file} keeps an unrelated alias byte-for-byte with ${config.name}`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-alias-fallback-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      const target = startupFor(resolveShell(config.env || {}));
      const rc = join(home, target.rc);
      mkdirSync(dirname(rc), { recursive: true });
      mkdirSync(bin, { recursive: true });
      const original = Buffer.concat([Buffer.from('# mine\n'), target.alias]);
      writeFileSync(rc, original, { mode: 0o600 });

      // Every startup file the fallback did NOT pick holds its own alias and
      // must come out byte-for-byte identical — never read, never created.
      const siblings = Object.entries(siblingSeeds)
        .filter(([rel]) => rel !== target.rc)
        .map(([rel, bytes]) => {
          const path = join(home, rel);
          mkdirSync(dirname(path), { recursive: true });
          writeFileSync(path, bytes, { mode: 0o600 });
          return { rel, path, bytes };
        });

      const run = () => {
        const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
          encoding: 'utf8',
          timeout: 30000,
          env: { HOME: home, PATH: '/usr/bin:/bin', ...config.env },
        });
        assert.ifError(result.error);
        assert.equal(result.status, 0, result.stderr);
        return result;
      };

      const first = run();
      assert.match(first.stdout, /added .* to PATH/);
      assert.ok(first.stdout.includes(rc), `the update resolved ${target.rc}, got: ${first.stdout}`);
      const updated = readFileSync(rc);
      assert.ok(updated.subarray(0, original.length).equals(original),
        'every original byte, alias included, is unchanged at its offset');
      assert.equal(updated.subarray(original.length).toString('utf8'),
        `\n${marker}\n${target.line(bin)}\n`, 'only the managed block is appended');
      for (const sibling of siblings) {
        assert.ok(readFileSync(sibling.path).equals(sibling.bytes),
          `${sibling.rel} is byte-for-byte untouched`);
      }

      const second = run();
      assert.equal(second.status, 0, second.stderr);
      assert.match(second.stdout, /already wired into/);
      assert.ok(readFileSync(rc).equals(updated), 'repeat run leaves all bytes unchanged');
    });
  }

  test(`${file} keeps a bash alias byte-for-byte in a marker-only file`, (t) => {
    // A startup file with the marker line but no PATH line is already wired
    // as far as `grep -qxF` is concerned: the update is a no-op, so the
    // unrelated alias and the missing PATH line stay exactly as they were.
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-alias-markeronly-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const home = join(root, 'home');
    const bin = join(root, 'live', 'bin');
    const rc = join(home, '.bashrc');
    mkdirSync(home, { recursive: true });
    mkdirSync(bin, { recursive: true });
    const original = Buffer.concat([Buffer.from('# mine\n'), bashAlias, Buffer.from(`${marker}\n`)]);
    writeFileSync(rc, original, { mode: 0o600 });

    const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
      encoding: 'utf8',
      timeout: 30000,
      env: { HOME: home, SHELL: '/bin/bash', PATH: '/usr/bin:/bin' },
    });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /already wired into/);
    assert.ok(readFileSync(rc).equals(original),
      'the marker-only file, alias included, is byte-for-byte unchanged');
  });

  test(`${file} keeps an unrelated alias byte-for-byte through a full install with SHELL unset`, (t) => {
    assert.ok(os && arch, 'test requires a supported Unix installer target');
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-alias-fallback-install-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const fixture = makeFixture(root, os, arch);
    const home = join(root, 'home');
    const bin = join(root, 'live', 'bin');
    const target = startupFor(resolveShell({}));
    const rc = join(home, target.rc);
    mkdirSync(dirname(rc), { recursive: true });
    const original = Buffer.concat([Buffer.from('# mine\n'), target.alias]);
    writeFileSync(rc, original, { mode: 0o600 });

    const siblings = Object.entries(siblingSeeds)
      .filter(([rel]) => rel !== target.rc)
      .map(([rel, bytes]) => {
        const path = join(home, rel);
        mkdirSync(dirname(path), { recursive: true });
        writeFileSync(path, bytes, { mode: 0o600 });
        return { rel, path, bytes };
      });

    const env = {
      HOME: home, PATH: '/usr/local/bin:/usr/bin:/bin',
      PHANTOM_INSTALL_DIR: bin, PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
      PHANTOM_TEST_LOCAL_RELEASE_DIR: fixture, PHANTOM_TAG: 'v1.2.3',
    };
    const run = () => spawnSync('/bin/bash', [installer], { encoding: 'utf8', timeout: 30000, env });

    const first = run();
    assert.ifError(first.error);
    assert.equal(first.status, 0, first.stderr);
    assert.match(first.stdout, /added .* to PATH/);
    assert.ok(first.stdout.includes(rc), `the update resolved ${target.rc}, got: ${first.stdout}`);
    const updated = readFileSync(rc);
    assert.ok(updated.subarray(0, original.length).equals(original),
      'every original byte, alias included, is unchanged at its offset');
    assert.equal(updated.subarray(original.length).toString('utf8'),
      `\n${marker}\n${target.line(bin)}\n`, 'only the managed block is appended');
    for (const sibling of siblings) {
      assert.ok(readFileSync(sibling.path).equals(sibling.bytes),
        `${sibling.rel} is byte-for-byte untouched`);
    }

    const second = run();
    assert.ifError(second.error);
    assert.equal(second.status, 0, second.stderr);
    assert.match(second.stdout, /already wired into/);
    assert.ok(readFileSync(rc).equals(updated), 'repeat install leaves all bytes unchanged');
  });
}
