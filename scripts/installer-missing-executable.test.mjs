import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const repo = resolve(import.meta.dirname, '..');
const installers = {
  repository: join(repo, 'scripts', 'install.sh'),
  public: join(repo, 'apps', 'web', 'public', 'install.sh'),
};
const os = { darwin: 'apple-darwin', linux: 'unknown-linux-gnu' }[process.platform];
const arch = { x64: 'x86_64', arm64: 'aarch64' }[process.arch];

// The archive is real and its checksum is valid, so the installer reaches the
// archive-contents checks; only an executable is missing from it.
for (const [name, installer] of Object.entries(installers)) {
  for (const members of [['phantom-mcp'], ['phantom'], ['README']]) {
    test(`${name} installer fails and keeps the existing install when the archive holds only ${members.join(',')}`, (t) => {
      assert.ok(os && arch, 'test requires a supported Unix installer target');
      const root = mkdtempSync(join(tmpdir(), 'phantom-missing-exe-'));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const [fixture, payload, home, install] = ['fixture', 'payload', 'home', join('live', 'bin')]
        .map((d) => join(root, d));
      for (const dir of [fixture, payload, home, install]) mkdirSync(dir, { recursive: true });
      const existing = '#!/bin/sh\necho old-phantom\n';
      writeFileSync(join(install, 'phantom'), existing);
      chmodSync(join(install, 'phantom'), 0o755);
      const before = statSync(join(install, 'phantom'));

      for (const m of members) writeFileSync(join(payload, m), 'fixture');
      const archive = `phantom-${arch}-${os}.tar.gz`;
      execFileSync('tar', ['-czf', join(fixture, archive), '-C', payload, ...members]);
      const digest = createHash('sha256').update(readFileSync(join(fixture, archive))).digest('hex');
      writeFileSync(join(fixture, `${archive}.sha256`), `${digest}  ${archive}\n`);

      const env = { ...process.env };
      for (const v of ['PHANTOM_REPO', 'PHANTOM_TEST_FAIL_AFTER_PROMOTION']) delete env[v];
      const result = spawnSync('/bin/bash', [installer], {
        encoding: 'utf8',
        timeout: 30000,
        env: {
          ...env,
          HOME: home,
          PHANTOM_INSTALL_DIR: install,
          PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
          PHANTOM_TEST_LOCAL_RELEASE_DIR: fixture,
          PHANTOM_TAG: 'v1.2.3',
        },
      });
      assert.ifError(result.error);
      assert.notEqual(result.status, 0);
      assert.match(result.stdout, /checksum verified/);
      assert.match(result.stderr, /release archive must contain exactly phantom and phantom-mcp/);
      assert.doesNotMatch(result.stdout, /installed to/);

      const after = statSync(join(install, 'phantom'));
      assert.equal(readFileSync(join(install, 'phantom'), 'utf8'), existing);
      assert.equal(after.mode & 0o777, 0o755);
      assert.equal(after.ino, before.ino, 'existing executable was not replaced');
      assert.deepEqual(readdirSync(install), ['phantom']);
      assert.deepEqual(readdirSync(join(root, 'live')), ['bin'], 'stage and lock are removed');
    });
  }
}
