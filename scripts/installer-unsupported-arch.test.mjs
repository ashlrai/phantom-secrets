import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync,
  realpathSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const repo = resolve(import.meta.dirname, '..');
const installers = {
  repository: join(repo, 'scripts', 'install.sh'),
  public: join(repo, 'apps', 'web', 'public', 'install.sh'),
};

// Real system tools the installer needs before it reaches the platform check,
// linked into the shim dir so PATH holds only these plus the stubs below.
const passthrough = [
  'basename', 'dirname', 'tr', 'mkdir', 'cat', 'mktemp', 'chmod', 'rm', 'sed', 'date', 'sleep',
  'kill', 'wc', 'awk', 'mv', 'cp', 'stat', 'find', 'grep', 'touch',
];

function shim(dir, name, body) {
  writeFileSync(join(dir, name), `#!/bin/sh\n${body}\n`);
  chmodSync(join(dir, name), 0o755);
}

function realTool(name) {
  for (const dir of ['/usr/bin', '/bin']) {
    if (existsSync(join(dir, name))) return join(dir, name);
  }
  throw new Error(`${name} not found`);
}

// `uname` is stubbed to report `sysname` / `machine`. curl and tar record any
// call in `calls.log`, so a test can prove nothing was fetched.
function run(installer, root, sysname, machine) {
  const shims = join(root, 'shims');
  const home = join(root, 'home');
  mkdirSync(shims);
  mkdirSync(home);
  for (const name of passthrough) symlinkSync(realTool(name), join(shims, name));
  const log = join(root, 'calls.log');
  shim(shims, 'uname', `case "$1" in -s) echo ${sysname} ;; -m) echo ${machine} ;; *) echo ${sysname} ;; esac`);
  shim(shims, 'curl', `echo "curl $*" >> "${log}"; exit 99`);
  shim(shims, 'tar', `echo "tar $*" >> "${log}"; exit 99`);
  const install = join(root, 'live', 'bin');
  const result = spawnSync('/bin/bash', [installer], {
    encoding: 'utf8',
    timeout: 30000,
    env: { HOME: home, SHELL: '/bin/bash', PATH: shims, PHANTOM_INSTALL_DIR: install },
  });
  return { result, install, log };
}

const cases = [
  { sysname: 'Linux', machine: 'i686', what: 'arch', value: 'i686' },
  { sysname: 'Darwin', machine: 'ppc64', what: 'arch', value: 'ppc64' },
  { sysname: 'Linux', machine: 'riscv64', what: 'arch', value: 'riscv64' },
  { sysname: 'Linux', machine: 'armv7l', what: 'arch', value: 'armv7l' },
  { sysname: 'FreeBSD', machine: 'x86_64', what: 'OS', value: 'FreeBSD' },
];

for (const [name, installer] of Object.entries(installers)) {
  for (const { sysname, machine, what, value } of cases) {
    test(`${name} installer rejects ${sysname}/${machine} before downloading`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-unsupported-arch-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const { result, install, log } = run(installer, root, sysname, machine);

      assert.ifError(result.error);
      assert.equal(result.status, 1);
      assert.match(result.stderr, new RegExp(`phantom: unsupported ${what}: ${value}`));
      assert.match(result.stderr, /releases/, 'error points at the releases page');
      assert.doesNotMatch(result.stdout, /target:|downloading|installed/i);
      assert.equal(existsSync(log), false, existsSync(log) ? readFileSync(log, 'utf8') : '');
      assert.equal(existsSync(install), false, 'install directory not created');
      assert.deepEqual(readdirSync(join(root, 'home')), [], 'home untouched');
      assert.deepEqual(readdirSync(root).sort(), ['home', 'shims']);
    });
  }

  test(`${name} installer accepts a supported uname and reaches the download step`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-supported-arch-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const { result, log } = run(installer, root, 'Linux', 'aarch64');

    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stdout, /target: aarch64-unknown-linux-gnu/);
    assert.doesNotMatch(result.stderr, /unsupported/);
    assert.match(readFileSync(log, 'utf8'), /^curl /, 'control: stub curl was reached');
  });
}
