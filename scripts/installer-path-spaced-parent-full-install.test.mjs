import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import test from 'node:test';

// Full installer run (local release fixture, real mktemp/cp/mv) with HOME in a
// directory whose name has spaces. The PATH entry must land in the intended
// startup file, and the decoy directories a word-split path would name
// ("my", "home", "dir", "my home") must stay empty.
const installers = [
  resolve(import.meta.dirname, 'install.sh'),
  resolve(import.meta.dirname, '../apps/web/public/install.sh'),
];
const shells = [
  { name: 'bash', rc: ['.bashrc'], line: (bin) => `export PATH="${bin}:$PATH"` },
  { name: 'zsh', rc: ['.zshrc'], line: (bin) => `export PATH="${bin}:$PATH"` },
  { name: 'fish', rc: ['.config', 'fish', 'config.fish'], line: (bin) => `set -gx PATH "${bin}" $PATH` },
];

for (const installer of installers) {
  for (const shell of shells) {
    test(`${installer.includes('apps') ? 'public' : 'scripts'} installer adds the ${shell.name} PATH entry under a spaced HOME without split-path files`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-spaced-full-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'my home dir');
      const decoys = ['my', 'home', 'dir', 'my home'].map((d) => join(root, d));
      const release = join(root, 'release');
      const payload = join(root, 'payload');
      const install = join(root, 'live', 'bin');
      for (const dir of [home, release, payload, ...decoys]) mkdirSync(dir);

      for (const name of ['phantom', 'phantom-mcp']) {
        writeFileSync(join(payload, name), `#!/bin/sh\nprintf '${name} 1.2.3\\n'\n`, { mode: 0o755 });
      }
      const os = { darwin: 'apple-darwin', linux: 'unknown-linux-gnu' }[process.platform];
      const arch = { x64: 'x86_64', arm64: 'aarch64' }[process.arch];
      assert.ok(os && arch, 'supported Unix installer target required');
      const archive = `phantom-${arch}-${os}.tar.gz`;
      const archivePath = join(release, archive);
      execFileSync('tar', ['-czf', archivePath, '-C', payload, 'phantom', 'phantom-mcp']);
      const digest = createHash('sha256').update(readFileSync(archivePath)).digest('hex');
      writeFileSync(`${archivePath}.sha256`, `${digest}  ${archive}\n`);

      const result = spawnSync('/bin/bash', [installer], {
        encoding: 'utf8',
        timeout: 30000,
        cwd: root,
        env: {
          HOME: home, SHELL: `/bin/${shell.name}`, PATH: '/usr/bin:/bin',
          PHANTOM_INSTALL_DIR: install, PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
          PHANTOM_TEST_LOCAL_RELEASE_DIR: release, PHANTOM_TAG: 'v1.2.3',
        },
      });
      assert.ifError(result.error);
      assert.equal(result.status, 0, result.stderr);

      const rc = join(home, ...shell.rc);
      assert.equal(readFileSync(rc, 'utf8'), `\n# phantom-secrets PATH\n${shell.line(install)}\n`);
      for (const decoy of decoys) {
        assert.deepEqual(readdirSync(decoy), [], `${basename(decoy)} was never written to`);
      }
      assert.deepEqual(readdirSync(dirname(rc)).filter((n) => n.startsWith('.phantom-path.')), []);
      assert.deepEqual(readdirSync(root).sort(),
        ['live', 'payload', 'release', ...decoys.map((d) => basename(d)), basename(home)].sort(),
        'nothing else appeared under the test root');
    });
  }
}
