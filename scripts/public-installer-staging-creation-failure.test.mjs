import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const installer = fileURLToPath(new URL('../apps/web/public/install.sh', import.meta.url));

test('public installer reports staging creation failure and preserves the existing install', (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-stage-failure-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const home = join(root, 'home');
  const shims = join(root, 'shims');
  const parent = join(root, 'install parent');
  const install = join(parent, 'bin');
  const log = join(root, 'mktemp-args');
  for (const dir of [home, shims, install]) mkdirSync(dir, { recursive: true });
  writeFileSync(join(install, 'old-install'), 'preserve-me');
  writeFileSync(join(shims, 'mktemp'), '#!/bin/sh\nprintf "%s\\n" "$@" > "$STAGE_TEST_LOG"\nexit 42\n', { mode: 0o755 });
  // Prevent any network request even if a regression continues past staging.
  writeFileSync(join(shims, 'curl'), '#!/bin/sh\nexit 99\n', { mode: 0o755 });

  const env = { ...process.env };
  for (const name of Object.keys(env)) if (name.startsWith('PHANTOM_')) delete env[name];
  const result = spawnSync('/bin/bash', [installer], {
    encoding: 'utf8', timeout: 30000,
    env: { ...env, HOME: home, PATH: `${shims}:${env.PATH}`, PHANTOM_INSTALL_DIR: install, STAGE_TEST_LOG: log },
  });
  assert.ifError(result.error);
  assert.notEqual(result.status, 0, 'installer must fail');
  assert.match(result.stderr, /could not create a private staging directory/);
  assert.deepEqual(readFileSync(log, 'utf8').trimEnd().split('\n'), ['-d', join(parent, '.bin.install.XXXXXX')]);
  assert.doesNotMatch(result.stdout, /downloading|installed to/);
  assert.equal(readFileSync(join(install, 'old-install'), 'utf8'), 'preserve-me');
  assert.deepEqual(readdirSync(parent), ['bin'], 'no staging directory or install lock remains');
});
