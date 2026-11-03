import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, realpathSync,
  rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const repo = resolve(import.meta.dirname, '..');
const installers = {
  repository: join(repo, 'scripts', 'install.sh'),
  public: join(repo, 'apps', 'web', 'public', 'install.sh'),
};

// Stub `uname` to report an OS/arch pair; stub `curl` and `tar` to record any
// call, so the test can prove nothing was downloaded.
function run(installer, root, os, machine) {
  const shims = join(root, 'shims');
  mkdirSync(shims);
  const stub = (name, body) => {
    writeFileSync(join(shims, name), `#!/bin/sh\n${body}\n`);
    chmodSync(join(shims, name), 0o755);
  };
  stub('uname', `case "$1" in -s) echo ${os};; -m) echo ${machine};; esac`);
  const calls = join(root, 'calls.log');
  stub('curl', `echo curl >> '${calls}'; exit 99`);
  stub('tar', `echo tar >> '${calls}'; exit 99`);
  const home = join(root, 'home');
  const install = join(root, 'live', 'bin');
  mkdirSync(home);
  const result = spawnSync('/bin/bash', [installer], {
    encoding: 'utf8',
    timeout: 30000,
    env: {
      HOME: home, SHELL: '/bin/bash', PHANTOM_INSTALL_DIR: install,
      PATH: `${shims}:/usr/bin:/bin`,
    },
  });
  return { result, install, calls };
}

const cases = [
  { os: 'Linux', machine: 'riscv64', label: 'arch', shown: 'unsupported arch: riscv64' },
  { os: 'Linux', machine: 'armv7l', label: 'arch', shown: 'unsupported arch: armv7l' },
  { os: 'Darwin', machine: 'i386', label: 'arch', shown: 'unsupported arch: i386' },
  { os: 'FreeBSD', machine: 'x86_64', label: 'OS', shown: 'unsupported OS: FreeBSD' },
];

for (const [name, installer] of Object.entries(installers)) {
  for (const { os, machine, label, shown } of cases) {
    test(`${name} installer rejects unsupported ${label} ${os}/${machine} before downloading`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-unsupported-arch-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const { result, install, calls } = run(installer, root, os, machine);

      assert.ifError(result.error);
      assert.notEqual(result.status, 0);
      assert.equal(result.status, 1);
      assert.ok(result.stderr.includes(shown), result.stderr);
      assert.match(result.stderr, /releases/, 'error points at the release page');
      assert.doesNotMatch(result.stdout, /downloading|installed|target:/i);
      assert.equal(existsSync(calls), false, 'curl/tar never invoked');
      assert.equal(existsSync(install), false, 'install directory not created');
      assert.deepEqual(readdirSync(join(root, 'home')), [], 'home untouched');
    });
  }
}
