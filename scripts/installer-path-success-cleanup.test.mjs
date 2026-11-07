import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import test from 'node:test';

const installers = [resolve(import.meta.dirname, 'install.sh'), resolve(import.meta.dirname, '../apps/web/public/install.sh')];
const shells = [
  { name: 'bash', rc: '.bashrc', line: (bin) => `export PATH="${bin}:$PATH"` },
  { name: 'zsh', rc: '.zshrc', line: (bin) => `export PATH="${bin}:$PATH"` },
  { name: 'fish', rc: '.config/fish/config.fish', line: (bin) => `set -gx PATH "${bin}" $PATH` },
];

for (const installer of installers) for (const shell of shells) for (const existing of [false, true]) {
  test(`${basename(dirname(installer))} installer cleans PATH files after ${shell.name} install (existing rc: ${existing})`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-install-path-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const home = join(root, 'home with spaces');
    const release = join(root, 'release');
    const payload = join(root, 'payload');
    const shims = join(root, 'shims');
    const install = join(root, 'live', 'bin');
    for (const dir of [home, release, payload, shims]) mkdirSync(dir, { recursive: true });
    const rc = join(home, shell.rc);
    const original = '# existing configuration\n';
    if (existing) {
      mkdirSync(dirname(rc), { recursive: true });
      writeFileSync(rc, original);
    }
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
    const log = join(root, 'created');
    const mktemp = execFileSync('which', ['mktemp'], { encoding: 'utf8' }).trim();
    writeFileSync(join(shims, 'mktemp'), `#!/bin/sh\ncreated="$(${JSON.stringify(mktemp)} "$@")" || exit $?\ncase "$created" in */.phantom-path.*) printf '%s\\n' "$created" >> ${JSON.stringify(log)};; esac\nprintf '%s\\n' "$created"\n`);
    chmodSync(join(shims, 'mktemp'), 0o755);
    const result = spawnSync('/bin/bash', [installer], {
      encoding: 'utf8', timeout: 30000,
      env: { HOME: home, SHELL: `/bin/${shell.name}`, PATH: `${shims}:/usr/bin:/bin`,
        PHANTOM_INSTALL_DIR: install, PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
        PHANTOM_TEST_LOCAL_RELEASE_DIR: release, PHANTOM_TAG: 'v1.2.3' },
    });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /added .* to PATH/);
    assert.equal(readFileSync(rc, 'utf8'), `${existing ? original : ''}\n# phantom-secrets PATH\n${shell.line(install)}\n`);
    const created = readFileSync(log, 'utf8').trim().split('\n');
    assert.equal(created.length, 2);
    assert.match(basename(created[0]), /^\.phantom-path\.before\./);
    assert.match(basename(created[1]), /^\.phantom-path\.candidate\./);
    for (const path of created) {
      assert.equal(dirname(path), dirname(rc));
      assert.equal(existsSync(path), false, 'created temporary file was removed');
    }
    assert.deepEqual(readdirSync(dirname(rc)).filter((name) => /^\.phantom-path\.(before|candidate)\./.test(name)), []);
    assert.deepEqual(readdirSync(home, { recursive: true }).filter((name) => basename(name).startsWith('.phantom-path')), [], 'no .phantom-path files anywhere under home');
  });
}
