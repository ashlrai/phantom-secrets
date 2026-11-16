import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

// Full installer run (local release fixture) in which creating the temporary
// shell-configuration candidate fails. The installer must still finish the
// install, report that the PATH could not be updated, leave the user's
// startup file byte-for-byte and inode-for-inode unchanged, and leave no
// .phantom-path.* sibling behind. Function-level coverage of the same seam
// lives in installer-path-temp-failure.test.mjs.
const installers = {
  'scripts/install.sh': resolve(import.meta.dirname, 'install.sh'),
  'apps/web/public/install.sh': resolve(import.meta.dirname, '..', 'apps', 'web', 'public', 'install.sh'),
};

for (const [label, installer] of Object.entries(installers)) {
  test(`${label} reports a failed candidate temp file and preserves the startup file`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-candidate-create-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const home = join(root, 'home');
    const shims = join(root, 'shims');
    const release = join(root, 'release');
    const payload = join(root, 'payload');
    const install = join(root, 'live', 'bin');
    for (const dir of [home, shims, release, payload]) mkdirSync(dir);

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

    const rc = join(home, '.bashrc');
    const original = Buffer.from('# existing configuration\nexport EXAMPLE=unchanged\n');
    writeFileSync(rc, original, { mode: 0o600 });
    const before = lstatSync(rc);

    const realMktemp = execFileSync('which', ['mktemp'], { encoding: 'utf8' }).trim();
    const shim = join(shims, 'mktemp');
    writeFileSync(shim, `#!/bin/sh
case "$1" in *.phantom-path.candidate.*) exit 1 ;; esac
exec ${JSON.stringify(realMktemp)} "$@"
`);
    chmodSync(shim, 0o755);

    const result = spawnSync('/bin/bash', [installer], {
      encoding: 'utf8',
      timeout: 30000,
      cwd: root,
      env: {
        HOME: home, SHELL: '/bin/bash', PATH: `${shims}:/usr/bin:/bin`,
        PHANTOM_INSTALL_DIR: install, PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
        PHANTOM_TEST_LOCAL_RELEASE_DIR: release, PHANTOM_TAG: 'v1.2.3',
      },
    });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
    assert.ok(
      result.stderr.includes(`could not update your shell PATH; add ${install} manually`),
      'the failure is reported with the manual next step',
    );
    assert.ok(!result.stdout.includes('added '), 'no success message for the PATH update');
    assert.deepEqual(readFileSync(rc), original, 'startup file content is preserved');
    const after = lstatSync(rc);
    assert.equal(after.ino, before.ino, 'startup file is not replaced');
    assert.equal(after.mode, before.mode);
    assert.deepEqual(readdirSync(home), ['.bashrc'], 'no temporary siblings remain');
  });
}
