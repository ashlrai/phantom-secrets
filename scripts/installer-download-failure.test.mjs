import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync,
  realpathSync, rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';

const repo = resolve(import.meta.dirname, '..');
const installers = {
  repository: join(repo, 'scripts', 'install.sh'),
  public: join(repo, 'apps', 'web', 'public', 'install.sh'),
};

// A stubbed curl that records the staging path it was asked to write to,
// proves that path exists while curl runs, then fails like `curl --fail` on
// an HTTP error. Nothing touches the network.
function runInstaller(installer, root) {
  const shims = join(root, 'shims');
  mkdirSync(shims);
  writeFileSync(join(shims, 'curl'), `#!/bin/sh
# Answer the capability probe without failing; fail only real downloads.
case "$*" in *--help*) exit 0 ;; esac
out=""
while [ $# -gt 0 ]; do
  if [ "$1" = "--output" ]; then out="$2"; fi
  shift
done
printf '%s\\n' "$out" >> "$PHANTOM_TEST_CURL_LOG"
[ -d "$(dirname "$out")" ] && printf 'present\\n' >> "$PHANTOM_TEST_CURL_LOG"
printf 'curl: (22) The requested URL returned error: 404\\n' >&2
exit 22
`);
  chmodSync(join(shims, 'curl'), 0o755);
  const home = join(root, 'home');
  const install = join(root, 'live', 'bin');
  const curlLog = join(root, 'curl.log');
  mkdirSync(home);
  mkdirSync(install, { recursive: true });
  writeFileSync(join(install, 'old-install'), 'preserve-me');
  const env = { ...process.env };
  for (const name of [
    'PHANTOM_REPO', 'PHANTOM_TAG', 'PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES',
    'PHANTOM_TEST_LOCAL_RELEASE_DIR', 'PHANTOM_TEST_FAIL_AFTER_PROMOTION',
  ]) delete env[name];
  const result = spawnSync('/bin/bash', [installer], {
    encoding: 'utf8',
    timeout: 30000,
    env: {
      ...env,
      HOME: home,
      SHELL: '/bin/bash',
      PATH: `${shims}:${process.env.PATH}`,
      PHANTOM_INSTALL_DIR: install,
      PHANTOM_TEST_CURL_LOG: curlLog,
    },
  });
  return { result, install, curlLog };
}

for (const [name, installer] of Object.entries(installers)) {
  test(`${name} installer exits nonzero and removes its staging directory when the download fails`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-download-failure-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const { result, install, curlLog } = runInstaller(installer, root);
    const parent = dirname(install);

    assert.ifError(result.error);
    assert.notEqual(result.status, 0, 'a failed download must fail the install');
    assert.match(result.stdout, /downloading /);
    assert.doesNotMatch(result.stdout, /checksum|installed/i);

    const lines = readFileSync(curlLog, 'utf8').split('\n').filter(Boolean);
    assert.deepEqual(lines.slice(1, 2), ['present'], 'staging existed during the download');
    const stage = dirname(dirname(lines[0]));
    assert.equal(dirname(stage), parent);
    assert.match(stage, /\.bin\.install\.[A-Za-z0-9]{6}$/);
    assert.equal(lines.filter((l) => l !== 'present').length, 1, 'no second download after failure');
    assert.equal(existsSync(stage), false, 'staging directory must be removed');
    assert.equal(readFileSync(join(install, 'old-install'), 'utf8'), 'preserve-me');
    assert.deepEqual(readdirSync(parent), ['bin'], 'no lock or staging leftovers');
  });
}
