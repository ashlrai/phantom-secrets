import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

for (const [name, url] of Object.entries({
  repository: new URL('install.sh', import.meta.url),
  public: new URL('../apps/web/public/install.sh', import.meta.url),
})) {
  test(`${name} installer cleans up after failure with a custom TMPDIR`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-custom-tmp-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const [release, payload, home, shims, customTmp, install] =
      ['release', 'payload', 'home', 'shims', 'custom temp', 'live/bin'].map((p) => join(root, p));
    for (const dir of [release, payload, home, shims, customTmp, install]) mkdirSync(dir, { recursive: true });
    writeFileSync(join(customTmp, 'sentinel'), 'keep');
    writeFileSync(join(install, 'phantom'), 'old install');
    for (const binary of ['phantom', 'phantom-mcp']) writeFileSync(join(payload, binary), 'fixture');
    const os = { darwin: 'apple-darwin', linux: 'unknown-linux-gnu' }[process.platform];
    const arch = { x64: 'x86_64', arm64: 'aarch64' }[process.arch];
    assert.ok(os && arch, 'supported Unix installer target required');
    const archive = `phantom-${arch}-${os}.tar.gz`;
    execFileSync('tar', ['-czf', join(release, archive), '-C', payload, 'phantom', 'phantom-mcp']);
    writeFileSync(join(release, `${archive}.sha256`), `${'0'.repeat(64)}  ${archive}\n`);

    const record = join(root, 'created');
    const mktemp = execFileSync('which', ['mktemp'], { encoding: 'utf8' }).trim();
    writeFileSync(join(shims, 'mktemp'), `#!/bin/sh\nout="$(${JSON.stringify(mktemp)} "$@")" || exit $?\nprintf '%s\\n' "$out" >> ${JSON.stringify(record)}\nprintf '%s\\n' "$out"\n`, { mode: 0o755 });
    // Fail closed if the local release override ever stops preventing network access.
    writeFileSync(join(shims, 'curl'), '#!/bin/sh\nexit 99\n', { mode: 0o755 });
    const env = { ...process.env };
    for (const key of ['PHANTOM_REPO', 'PHANTOM_TEST_FAIL_AFTER_PROMOTION', 'PHANTOM_INSTALL_LOCK_WAIT_SECONDS', 'PHANTOM_INSTALL_LOCK_STALE_SECONDS', 'PHANTOM_INSTALL_LOCK_HEARTBEAT_SECONDS']) delete env[key];
    const result = spawnSync('/bin/bash', [fileURLToPath(url)], {
      encoding: 'utf8', timeout: 30000,
      env: { ...env, HOME: home, TMPDIR: customTmp, PATH: `${shims}:${env.PATH}`,
        PHANTOM_INSTALL_DIR: install, PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
        PHANTOM_TEST_LOCAL_RELEASE_DIR: release, PHANTOM_TAG: 'v1.2.3' },
    });
    assert.ifError(result.error);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /SHA-256 mismatch/);
    const created = readFileSync(record, 'utf8').trim().split('\n');
    assert.equal(created.length, 1, 'one private staging directory was created');
    assert.equal(dirname(created[0]), dirname(install), 'staging is beside the install for atomic promotion');
    assert.match(basename(created[0]), /^\.bin\.install\./);
    assert.equal(existsSync(created[0]), false, 'staging is removed after failure');
    assert.deepEqual(readdirSync(dirname(install)), ['bin'], 'lock and staging are removed');
    assert.equal(readFileSync(join(install, 'phantom'), 'utf8'), 'old install');
    assert.deepEqual(readdirSync(customTmp), ['sentinel'], 'custom TMPDIR has no leftover artifacts');
    assert.equal(readFileSync(join(customTmp, 'sentinel'), 'utf8'), 'keep');
    assert.deepEqual(readdirSync(home), []);
  });
}
