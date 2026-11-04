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
import { fileURLToPath } from 'node:url';

// A hand-edited shell startup file may not end in a newline. The installer
// appends its PATH block through a candidate copy with a leading newline, so
// the existing last line is preserved byte-for-byte (it only gains its missing
// terminator) while the marker and PATH line land on lines of their own instead
// of being glued onto the previous content. Binaries are stubs; nothing is
// downloaded.
const installers = {
  'scripts/install.sh': new URL('install.sh', import.meta.url),
  'apps/web/public/install.sh': new URL('../apps/web/public/install.sh', import.meta.url),
};

const shells = {
  bash: {
    shell: '/bin/bash',
    rcPath: (home) => join(home, '.bashrc'),
    pathLine: (install) => `export PATH="${install}:$PATH"`,
  },
  zsh: {
    shell: '/bin/zsh',
    rcPath: (home) => join(home, '.zshrc'),
    pathLine: (install) => `export PATH="${install}:$PATH"`,
  },
  fish: {
    shell: '/usr/bin/fish',
    rcPath: (home) => join(home, '.config', 'fish', 'config.fish'),
    pathLine: (install) => `set -gx PATH "${install}" $PATH`,
  },
};

// Deliberately lacks a final newline: the PATH append must not merge with the
// last line.
const original = '# user shell config\nexport EDITOR=vim';

for (const [label, url] of Object.entries(installers)) {
  for (const [shellName, config] of Object.entries(shells)) {
    test(`${label} adds separate PATH lines to a ${shellName} startup file without a final newline`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-installer-newline-')));
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
      execFileSync('tar', ['-czf', join(fixture, archive), '-C', payload, 'phantom', 'phantom-mcp']);
      const digest = createHash('sha256').update(readFileSync(join(fixture, archive))).digest('hex');
      writeFileSync(join(fixture, `${archive}.sha256`), `${digest}  ${archive}\n`);

      const rc = config.rcPath(home);
      mkdirSync(dirname(rc), { recursive: true });
      writeFileSync(rc, original, { mode: 0o600 });

      const env = { ...process.env };
      for (const name of ['PHANTOM_REPO', 'PHANTOM_TEST_FAIL_AFTER_PROMOTION',
        'PHANTOM_INSTALL_LOCK_WAIT_SECONDS', 'PHANTOM_INSTALL_LOCK_STALE_SECONDS',
        'PHANTOM_INSTALL_LOCK_HEARTBEAT_SECONDS']) delete env[name];
      const result = spawnSync('/bin/bash', [fileURLToPath(url)], {
        encoding: 'utf8',
        timeout: 30000,
        env: {
          ...env,
          HOME: home,
          SHELL: config.shell,
          PHANTOM_INSTALL_DIR: install,
          PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
          PHANTOM_TEST_LOCAL_RELEASE_DIR: fixture,
          PHANTOM_TAG: 'v1.2.3',
        },
      });
      assert.ifError(result.error);
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, /added .* to PATH/);

      const updated = readFileSync(rc, 'utf8');
      assert.equal(updated,
        `${original}\n# phantom-secrets PATH\n${config.pathLine(install)}\n`);
      const lines = updated.split('\n');
      assert.ok(lines.includes('export EDITOR=vim'),
        'the unterminated last line is preserved as its own line');
      assert.equal(lines.filter((line) => line === '# phantom-secrets PATH').length, 1,
        'the marker is a separate line');
      assert.ok(lines.includes(config.pathLine(install)),
        'the PATH line is a separate line');
      assert.equal(statSync(rc).mode & 0o777, 0o600, 'startup file mode is preserved');
      assert.deepEqual(
        readdirSync(dirname(rc)).filter((name) => name.startsWith('.phantom-path.')),
        [],
        'no PATH-update temporary files remain beside the startup file',
      );
    });
  }
}
