import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';

const repo = resolve(import.meta.dirname, '..');
for (const [label, installer] of [
  ['repository', join(repo, 'scripts/install.sh')],
  ['public', join(repo, 'apps/web/public/install.sh')],
]) {
  test(`${label} installer cleans staging after download failure with a nonexistent install parent`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-missing-parent-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const home = join(root, 'home');
    const shims = join(root, 'shims');
    const parent = join(root, 'new parent', 'nested');
    const install = join(parent, 'bin');
    const log = join(root, 'download-path');
    mkdirSync(home);
    mkdirSync(shims);
    writeFileSync(join(shims, 'curl'), `#!/bin/sh
case "$*" in *--help*) exit 0 ;; esac
while [ "$#" -gt 0 ]; do
  if [ "$1" = --output ]; then
    [ -d "$(dirname "$2")" ] || exit 99
    printf '%s\\n' "$2" > "$PHANTOM_TEST_CURL_LOG"
    printf 'partial download' > "$2"
    break
  fi
  shift
done
printf 'curl: simulated download failure\\n' >&2
exit 22
`);
    chmodSync(join(shims, 'curl'), 0o755);
    assert.equal(existsSync(parent), false, 'parent starts absent');
    const result = spawnSync('/bin/bash', [installer], {
      encoding: 'utf8', timeout: 30000,
      env: { HOME: home, SHELL: '/bin/bash', PATH: `${shims}:${process.env.PATH}`,
        PHANTOM_INSTALL_DIR: install, PHANTOM_TEST_CURL_LOG: log },
    });
    assert.ifError(result.error);
    assert.notEqual(result.status, 0, 'download failure must fail the installation');
    assert.match(result.stderr, /simulated download failure/);
    assert.doesNotMatch(result.stdout, /installed to/);
    const stage = dirname(dirname(readFileSync(log, 'utf8').trim()));
    assert.equal(dirname(stage), parent, 'download was staged in the newly created parent');
    assert.match(stage, /\.bin\.install\.[A-Za-z0-9]{6}$/);
    assert.equal(existsSync(stage), false, 'populated staging directory was removed');
    assert.equal(existsSync(install), false, 'failed install was not promoted');
    assert.deepEqual(readdirSync(parent), [], 'no staging or lock remains');
  });
}
