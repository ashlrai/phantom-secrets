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

// The installer documents that it promotes a private sibling candidate into
// ~/.phantom-secrets/bin, so its default staging root is ~/.phantom-secrets,
// not the system temp directory. A stubbed curl records where it was told to
// download, then fails; nothing touches the network.
function run(installer, root, { tmpdirValue } = {}) {
  const shims = join(root, 'shims');
  const home = join(root, 'home');
  const curlLog = join(root, 'curl.log');
  mkdirSync(shims);
  mkdirSync(home);
  writeFileSync(join(shims, 'curl'), `#!/bin/sh
case "$*" in *--help*) exit 0 ;; esac
out=""
while [ $# -gt 0 ]; do
  if [ "$1" = "--output" ]; then out="$2"; fi
  shift
done
printf '%s\\n' "$out" >> "$PHANTOM_TEST_CURL_LOG"
exit 22
`);
  chmodSync(join(shims, 'curl'), 0o755);
  const env = { ...process.env };
  for (const name of [
    'TMPDIR', 'PHANTOM_INSTALL_DIR', 'PHANTOM_REPO', 'PHANTOM_TAG',
    'PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES', 'PHANTOM_TEST_LOCAL_RELEASE_DIR',
    'PHANTOM_TEST_FAIL_AFTER_PROMOTION',
  ]) delete env[name];
  if (tmpdirValue) env.TMPDIR = tmpdirValue;
  const result = spawnSync('/bin/bash', [installer], {
    encoding: 'utf8',
    timeout: 30000,
    env: { ...env, HOME: home, SHELL: '/bin/bash', PATH: `${shims}:${process.env.PATH}`, PHANTOM_TEST_CURL_LOG: curlLog },
  });
  assert.ifError(result.error);
  assert.notEqual(result.status, 0, 'the stubbed download fails the install');
  const outputs = readFileSync(curlLog, 'utf8').split('\n').filter(Boolean);
  assert.ok(outputs.length > 0, 'installer reached the download step');
  return { home, stage: dirname(dirname(outputs[0])) };
}

for (const [name, installer] of Object.entries(installers)) {
  test(`${name} installer stages under ~/.phantom-secrets when TMPDIR is unset`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-default-stage-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const { home, stage } = run(installer, root);
    const defaultRoot = join(home, '.phantom-secrets');

    assert.equal(dirname(stage), defaultRoot);
    assert.match(stage, /\.bin\.install\.[A-Za-z0-9]{6}$/);
    assert.equal(existsSync(stage), false, 'staging is removed after the failure');
    assert.deepEqual(readdirSync(defaultRoot), [], 'no staging or lock leftovers');
  });

  test(`${name} installer ignores a TMPDIR value and still stages beside the install`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-default-stage-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const other = join(root, 'other-tmp');
    mkdirSync(other);
    const { home, stage } = run(installer, root, { tmpdirValue: other });

    assert.equal(dirname(stage), join(home, '.phantom-secrets'));
    assert.deepEqual(readdirSync(other), [], 'TMPDIR is never used for staging');
  });
}
