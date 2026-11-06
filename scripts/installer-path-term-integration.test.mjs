import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

for (const installer of ['install.sh', '../apps/web/public/install.sh']) {
  test(`${installer} preserves an unrelated TERM export through a complete PATH update`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-term-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const fixture = join(root, 'release');
    const payload = join(root, 'payload');
    const home = join(root, 'home');
    const bin = join(root, 'live', 'bin');
    for (const dir of [fixture, payload, home]) mkdirSync(dir, { recursive: true });
    const rc = join(home, '.bashrc');
    const original = Buffer.from('# shell settings\r\nexport TERM="xterm-256color"  # keep terminal settings\r\n# last line');
    writeFileSync(rc, original);
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
    const env = {
      HOME: home, SHELL: '/bin/bash', PATH: '/usr/local/bin:/usr/bin:/bin',
      PHANTOM_INSTALL_DIR: bin, PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
      PHANTOM_TEST_LOCAL_RELEASE_DIR: fixture, PHANTOM_TAG: 'v1.2.3',
    };
    const run = () => spawnSync('/bin/bash', [fileURLToPath(new URL(installer, import.meta.url))],
      { encoding: 'utf8', timeout: 30000, env });
    const first = run();
    assert.ifError(first.error);
    assert.equal(first.status, 0, first.stderr);
    assert.match(first.stdout, /added .* to PATH/);
    const updated = readFileSync(rc);
    assert.deepEqual(updated, Buffer.concat([original,
      Buffer.from(`\n# phantom-secrets PATH\nexport PATH="${bin}:$PATH"\n`)]));
    const shell = spawnSync('/bin/bash', ['--noprofile', '--norc', '-c',
      '. "$HOME/.bashrc"; printf %s "$PATH"'], { encoding: 'utf8', env });
    assert.ifError(shell.error);
    assert.equal(shell.status, 0, shell.stderr);
    assert.equal(shell.stdout, `${bin}:${env.PATH}`);
    const second = run();
    assert.ifError(second.error);
    assert.equal(second.status, 0, second.stderr);
    assert.match(second.stdout, /already wired into/);
    assert.deepEqual(readFileSync(rc), updated, 'repeat installation leaves all bytes unchanged');
  });
}
