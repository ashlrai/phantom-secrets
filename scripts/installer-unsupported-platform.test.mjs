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

// Stubbed platform probe: `uname -s` / `uname -m` print the fake values. A
// stubbed curl records any call, so the test can prove nothing was downloaded.
function run(installer, root, { os, arch }) {
  const shims = join(root, 'shims');
  mkdirSync(shims);
  writeFileSync(join(shims, 'uname'), `#!/bin/sh
case "$1" in -s) printf '%s\\n' "$PHANTOM_TEST_OS" ;; -m) printf '%s\\n' "$PHANTOM_TEST_ARCH" ;; esac
`);
  writeFileSync(join(shims, 'curl'), `#!/bin/sh
printf 'called\\n' >> "$PHANTOM_TEST_CURL_LOG"
exit 1
`);
  chmodSync(join(shims, 'uname'), 0o755);
  chmodSync(join(shims, 'curl'), 0o755);
  const home = join(root, 'home');
  const install = join(root, 'live', 'bin');
  mkdirSync(home);
  const env = { ...process.env };
  for (const name of [
    'PHANTOM_REPO', 'PHANTOM_TAG', 'PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES',
    'PHANTOM_TEST_LOCAL_RELEASE_DIR', 'PHANTOM_TEST_FAIL_AFTER_PROMOTION',
  ]) delete env[name];
  const curlLog = join(root, 'curl.log');
  const result = spawnSync('/bin/bash', [installer], {
    encoding: 'utf8',
    timeout: 30000,
    env: {
      ...env,
      HOME: home,
      SHELL: '/bin/bash',
      PATH: `${shims}:${process.env.PATH}`,
      PHANTOM_INSTALL_DIR: install,
      PHANTOM_TEST_OS: os,
      PHANTOM_TEST_ARCH: arch,
      PHANTOM_TEST_CURL_LOG: curlLog,
    },
  });
  return { result, root, curlLog };
}

const cases = [
  { label: 'operating system', os: 'FreeBSD', arch: 'x86_64', message: /unsupported OS: FreeBSD/ },
  { label: 'operating system (Windows shell)', os: 'MINGW64_NT-10.0', arch: 'x86_64', message: /unsupported OS: MINGW64_NT-10\.0/ },
  { label: 'architecture', os: 'Linux', arch: 'riscv64', message: /unsupported arch: riscv64/ },
];

for (const [name, installer] of Object.entries(installers)) {
  for (const { label, os, arch, message } of cases) {
    test(`${name} installer rejects an unsupported ${label} without downloading`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-unsupported-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const { result, curlLog } = run(installer, root, { os, arch });

      assert.ifError(result.error);
      assert.notEqual(result.status, 0, 'an unsupported platform must fail the install');
      assert.match(result.stderr, message);
      assert.match(result.stderr, /github\.com\/ashlrai\/phantom-secrets\/releases/);
      assert.doesNotMatch(result.stdout, /downloading|installed/i);
      assert.equal(existsSync(curlLog), false, 'curl must never be invoked');
      assert.equal(existsSync(join(root, 'live')), false, 'nothing is created for the install');
      assert.deepEqual(readdirSync(join(root, 'home')), [], 'home is untouched');
    });
  }
}
