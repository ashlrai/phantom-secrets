import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const root = fileURLToPath(new URL('..', import.meta.url));
const paths = ['scripts/install.sh', 'apps/web/public/install.sh'];
const guide = readFileSync(new URL('../docs/installer-copy-sync.md', import.meta.url), 'utf8');
const command = guide.match(/```sh\n([\s\S]*?)\n```/)?.[1];

test('the documented comparison identifies and compares the checked-in installers', () => {
  for (const path of paths) assert.ok(guide.includes(`](../${path})`));
  assert.ok(command, 'The guide must include a comparison command');
  const result = spawnSync('/bin/sh', ['-c', command], { cwd: root, encoding: 'utf8' });
  assert.ifError(result.error);
  const equal = readFileSync(join(root, paths[0])).equals(readFileSync(join(root, paths[1])));
  assert.equal(result.status, equal ? 0 : 1, result.stderr);
});

test('the documented command distinguishes matching, different, and missing files', () => {
  assert.ok(command, 'The guide must include a comparison command');
  const directory = mkdtempSync(join(tmpdir(), 'phantom-installer-sync-'));
  try {
    for (const path of paths) mkdirSync(join(directory, path, '..'), { recursive: true });
    const run = () => spawnSync('/bin/sh', ['-c', command], { cwd: directory, encoding: 'utf8' });
    const missing = run();
    assert.ifError(missing.error);
    assert.ok(missing.status > 1);

    for (const path of paths) writeFileSync(join(directory, path), 'same\n');
    assert.equal(run().status, 0);

    writeFileSync(join(directory, paths[1]), 'different\n');
    const different = run();
    assert.equal(different.status, 1);
    assert.match(different.stdout, /-same\n\+different/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
