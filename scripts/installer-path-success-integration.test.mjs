import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

for (const installer of ['install.sh', '../apps/web/public/install.sh']) {
  for (const shell of ['bash', 'fish']) {
    test(`${installer} cleans PATH temporary files after a successful ${shell} install`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-success-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const fixture = join(root, 'fixture');
      const payload = join(root, 'payload');
      const shims = join(root, 'shims');
      const install = join(root, 'live', 'bin');
      const rc = shell === 'fish' ? join(home, '.config', 'fish', 'config.fish') : join(home, '.bashrc');
      for (const dir of [dirname(rc), fixture, payload, shims]) mkdirSync(dir, { recursive: true });
      const original = '# existing configuration\n';
      writeFileSync(rc, original);
      for (const name of ['phantom', 'phantom-mcp']) {
        writeFileSync(join(payload, name), `#!/bin/sh\necho '${name} 1.2.3'\n`, { mode: 0o755 });
      }
      const os = { darwin: 'apple-darwin', linux: 'unknown-linux-gnu' }[process.platform];
      const arch = { x64: 'x86_64', arm64: 'aarch64' }[process.arch];
      assert.ok(os && arch, 'supported Unix installer target');
      const archive = `phantom-${arch}-${os}.tar.gz`;
      execFileSync('tar', ['-czf', join(fixture, archive), '-C', payload, 'phantom', 'phantom-mcp']);
      const digest = createHash('sha256').update(readFileSync(join(fixture, archive))).digest('hex');
      writeFileSync(join(fixture, `${archive}.sha256`), `${digest}  ${archive}\n`);

      // Record real mktemp results so absence cannot pass without exercising both allocations.
      const log = join(root, 'created');
      const mktemp = execFileSync('which', ['mktemp'], { encoding: 'utf8' }).trim();
      writeFileSync(join(shims, 'mktemp'), `#!/bin/sh\ncreated="$(${JSON.stringify(mktemp)} "$@")" || exit\nprintf '%s\\n' "$created" >> "$TEST_CREATED"\nprintf '%s\\n' "$created"\n`, { mode: 0o755 });
      const result = spawnSync('/bin/bash', [fileURLToPath(new URL(installer, import.meta.url))], {
        encoding: 'utf8', timeout: 30000,
        env: { HOME: home, SHELL: `/bin/${shell}`, PATH: `${shims}:/usr/local/bin:/usr/bin:/bin`,
          TEST_CREATED: log, PHANTOM_INSTALL_DIR: install, PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
          PHANTOM_TEST_LOCAL_RELEASE_DIR: fixture, PHANTOM_TAG: 'v1.2.3' },
      });
      assert.ifError(result.error);
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, /added .* to PATH/);
      for (const name of ['phantom', 'phantom-mcp']) assert.ok(existsSync(join(install, name)));
      const created = readFileSync(log, 'utf8').trim().split('\n').filter((p) => basename(p).startsWith('.phantom-path.'));
      assert.equal(created.length, 2);
      assert.match(basename(created[0]), /^\.phantom-path\.before\./);
      assert.match(basename(created[1]), /^\.phantom-path\.candidate\./);
      for (const path of created) {
        assert.equal(dirname(path), dirname(rc));
        assert.equal(existsSync(path), false);
      }
      assert.deepEqual(readdirSync(dirname(rc)), [basename(rc)]);
      const line = shell === 'fish' ? `set -gx PATH "${install}" $PATH` : `export PATH="${install}:$PATH"`;
      assert.equal(readFileSync(rc, 'utf8'), `${original}\n# phantom-secrets PATH\n${line}\n`);
    });
  }
}
