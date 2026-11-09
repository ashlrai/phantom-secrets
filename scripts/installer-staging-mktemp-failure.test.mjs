import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

for (const [name, url] of Object.entries({
  repository: new URL('install.sh', import.meta.url),
  public: new URL('../apps/web/public/install.sh', import.meta.url),
})) {
  test(`${name} installer preserves the destination when staging creation fails`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-stage-failure-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const home = join(root, 'home');
    const shims = join(root, 'shims');
    const install = join(root, 'live', 'bin');
    for (const dir of [home, shims, install]) mkdirSync(dir, { recursive: true });
    const existing = join(install, 'phantom');
    writeFileSync(existing, 'existing installation\n', { mode: 0o751 });
    const before = statSync(existing);
    const record = join(root, 'mktemp-args');
    writeFileSync(join(shims, 'mktemp'), '#!/bin/sh\nprintf "%s\\n" "$@" > "$RECORD"\nexit 42\n', { mode: 0o755 });
    writeFileSync(join(shims, 'curl'), '#!/bin/sh\ntouch "$DOWNLOADED"\nexit 1\n', { mode: 0o755 });
    const result = spawnSync('/bin/bash', [fileURLToPath(url)], {
      encoding: 'utf8', timeout: 30000,
      env: { HOME: home, PATH: `${shims}:/usr/bin:/bin:/usr/sbin:/sbin`,
        PHANTOM_INSTALL_DIR: install, RECORD: record, DOWNLOADED: join(root, 'downloaded') },
    });
    assert.ifError(result.error);
    assert.ok(Number.isInteger(result.status) && result.status !== 0, 'installer exits nonzero');
    assert.match(result.stderr, /could not create a private staging directory/);
    assert.equal(readFileSync(record, 'utf8'), `-d\n${dirname(install)}/.bin.install.XXXXXX\n`);
    assert.deepEqual(readdirSync(dirname(install)), ['bin'], 'lock and staging leave no siblings');
    assert.deepEqual(readdirSync(install), ['phantom']);
    assert.equal(readFileSync(existing, 'utf8'), 'existing installation\n');
    const after = statSync(existing);
    assert.equal(after.ino, before.ino, 'existing file was not replaced');
    assert.equal(after.mode, before.mode, 'existing permissions are unchanged');
    assert.deepEqual(readdirSync(home), [], 'HOME remains unchanged');
    assert.deepEqual(readdirSync(root).sort(), ['home', 'live', 'mktemp-args', 'shims'], 'no download attempted');
  });
}
