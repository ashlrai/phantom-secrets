import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

// The fixture's first line is a comment; the PATH update must only append, never touch it.
const fixtureRc = fileURLToPath(new URL('fixtures/installer-path/leading-comment.rc', import.meta.url));
const rcByShell = { bash: '.bashrc', zsh: '.zshrc', fish: '.config/fish/config.fish' };

for (const installer of ['install.sh', '../apps/web/public/install.sh']) {
  for (const [shell, rcName] of Object.entries(rcByShell)) {
    test(`${installer} keeps a leading comment unchanged when updating ${shell} PATH`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-leading-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const [release, payload, home] = ['release', 'payload', 'home'].map((d) => join(root, d));
      const bin = join(root, 'live', 'bin');
      for (const dir of [release, payload, home]) mkdirSync(dir, { recursive: true });
      const rc = join(home, rcName);
      mkdirSync(dirname(rc), { recursive: true });
      copyFileSync(fixtureRc, rc);
      const original = readFileSync(fixtureRc);
      assert.equal(original.toString().split('\n')[0].startsWith('# '), true, 'fixture starts with a comment');
      for (const name of ['phantom', 'phantom-mcp']) {
        writeFileSync(join(payload, name), `#!/bin/sh\necho "${name} 1.2.3"\n`);
        chmodSync(join(payload, name), 0o755);
      }
      const os = { darwin: 'apple-darwin', linux: 'unknown-linux-gnu' }[process.platform];
      const arch = { x64: 'x86_64', arm64: 'aarch64' }[process.arch];
      assert.ok(os && arch, 'test requires a supported Unix installer target');
      const archive = `phantom-${arch}-${os}.tar.gz`;
      execFileSync('tar', ['-czf', join(release, archive), '-C', payload, 'phantom', 'phantom-mcp']);
      const digest = createHash('sha256').update(readFileSync(join(release, archive))).digest('hex');
      writeFileSync(join(release, `${archive}.sha256`), `${digest}  ${archive}\n`);
      const result = spawnSync('/bin/bash', [fileURLToPath(new URL(installer, import.meta.url))], {
        encoding: 'utf8', timeout: 30000,
        env: {
          HOME: home, SHELL: `/bin/${shell}`, PATH: '/usr/local/bin:/usr/bin:/bin',
          PHANTOM_INSTALL_DIR: bin, PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
          PHANTOM_TEST_LOCAL_RELEASE_DIR: release, PHANTOM_TAG: 'v1.2.3',
        },
      });
      assert.ifError(result.error);
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, /added .* to PATH/);
      const updated = readFileSync(rc);
      assert.deepEqual(updated.subarray(0, original.length), original, 'original bytes, including the leading comment, are unchanged');
      const line = shell === 'fish' ? `set -gx PATH "${bin}" $PATH` : `export PATH="${bin}:$PATH"`;
      assert.equal(updated.subarray(original.length).toString(), `\n# phantom-secrets PATH\n${line}\n`);
    });
  }
}
