import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

// The extracted-function harness in installer-path-alias-bytes.test.mjs proves
// add_to_user_path preserves an unrelated alias; this file proves the same
// guarantee holds through a complete offline install.sh run — download,
// checksum, archive-shape validation, promotion, and the real PATH update —
// for every startup file the installer can pick. The alias payloads carry the
// bytes a sloppy rewrite would mangle (quotes, `$`, backticks, backslashes,
// tabs, trailing spaces, CRLF endings), so comparisons stay on raw Buffers. A
// second install must leave the file untouched, and a bash leg sources the
// updated .bashrc to prove the alias still expands, not just still exists.
const installers = {
  'scripts/install.sh': new URL('install.sh', import.meta.url),
  'apps/web/public/install.sh': new URL('../apps/web/public/install.sh', import.meta.url),
};

const marker = '# phantom-secrets PATH';
const shells = {
  bash: {
    shell: '/bin/bash',
    rc: (h) => join(h, '.bashrc'),
    line: (b) => `export PATH="${b}:$PATH"`,
    alias: Buffer.from('alias gs=\'git status -sb \\\n  && echo "done: $(date) `id -un`"\'\t  \r\n'),
    sibling: (h) => join(h, '.zshrc'),
  },
  zsh: {
    shell: '/bin/zsh',
    rc: (h) => join(h, '.zshrc'),
    line: (b) => `export PATH="${b}:$PATH"`,
    alias: Buffer.from('alias -g L=\'| less -R\' # café ✓\t \r\n'),
    sibling: (h) => join(h, '.bashrc'),
  },
  fish: {
    shell: '/usr/bin/fish',
    rc: (h) => join(h, '.config', 'fish', 'config.fish'),
    line: (b) => `set -gx PATH "${b}" $PATH`,
    alias: Buffer.from('alias gs "git status -sb; echo \\"$USER\\"" \t \r\n'),
    sibling: (h) => join(h, '.bashrc'),
  },
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

for (const [label, url] of Object.entries(installers)) {
  const installer = fileURLToPath(url);
  for (const [name, config] of Object.entries(shells)) {
    test(`${label} keeps an unrelated ${name} alias byte-for-byte through a full install`, (t) => {
      assert.ok(os && arch, 'test requires a supported Unix installer target');
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-alias-integration-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const fixture = makeFixture(root, os, arch);
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      const rc = config.rc(home);
      mkdirSync(dirname(rc), { recursive: true });
      const original = Buffer.concat([Buffer.from('# mine\n'), config.alias, Buffer.from('alias ll="ls -la"\n')]);
      writeFileSync(rc, original, { mode: 0o600 });

      // An alias in a different shell's startup file is never even read.
      const sibling = config.sibling(home);
      const siblingBytes = Buffer.from('alias sc="systemctl --user status"\t \r\n');
      writeFileSync(sibling, siblingBytes, { mode: 0o600 });

      const env = {
        HOME: home, SHELL: config.shell, PATH: '/usr/local/bin:/usr/bin:/bin',
        PHANTOM_INSTALL_DIR: bin, PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
        PHANTOM_TEST_LOCAL_RELEASE_DIR: fixture, PHANTOM_TAG: 'v1.2.3',
      };
      const run = () => spawnSync('/bin/bash', [installer], { encoding: 'utf8', timeout: 30000, env });

      const first = run();
      assert.ifError(first.error);
      assert.equal(first.status, 0, first.stderr);
      assert.match(first.stdout, /added .* to PATH/);

      const updated = readFileSync(rc);
      assert.ok(updated.subarray(0, original.length).equals(original),
        'every original byte, alias included, is unchanged at its offset');
      assert.equal(updated.subarray(original.length).toString('utf8'),
        `\n${marker}\n${config.line(bin)}\n`, 'only the managed block is appended');
      assert.ok(readFileSync(sibling).equals(siblingBytes),
        'the other shell\'s startup file is byte-for-byte untouched');

      const second = run();
      assert.ifError(second.error);
      assert.equal(second.status, 0, second.stderr);
      assert.match(second.stdout, /already wired into/);
      assert.ok(readFileSync(rc).equals(updated), 'repeat install leaves all bytes unchanged');
    });
  }

  test(`${label} leaves a bash alias working after a full install`, (t) => {
    assert.ok(os && arch, 'test requires a supported Unix installer target');
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-alias-eval-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const fixture = makeFixture(root, os, arch);
    const home = join(root, 'home');
    const bin = join(root, 'live', 'bin');
    const rc = join(home, '.bashrc');
    mkdirSync(home, { recursive: true });
    writeFileSync(rc, 'alias ll="ls -la"\nexport EDITOR=vim\n', { mode: 0o600 });
    const env = {
      HOME: home, SHELL: '/bin/bash', PATH: '/usr/local/bin:/usr/bin:/bin',
      PHANTOM_INSTALL_DIR: bin, PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
      PHANTOM_TEST_LOCAL_RELEASE_DIR: fixture, PHANTOM_TAG: 'v1.2.3',
    };
    const install = spawnSync('/bin/bash', [installer], { encoding: 'utf8', timeout: 30000, env });
    assert.ifError(install.error);
    assert.equal(install.status, 0, install.stderr);

    // Source the updated .bashrc in a clean bash: the unrelated alias and
    // export must still evaluate, and the installer bin dir must lead PATH.
    const check = spawnSync('/bin/bash', [
      '--noprofile', '--norc', '-c',
      'shopt -s expand_aliases; . "$HOME/.bashrc" && '
      + 'alias ll >/dev/null && [[ "$EDITOR" == vim ]] && [[ "$PATH" == "$1:"* ]]',
      'path-test', bin,
    ], { encoding: 'utf8', timeout: 30000, env: { HOME: home, PATH: env.PATH } });
    assert.ifError(check.error);
    assert.equal(check.status, 0, check.stderr);
  });
}
