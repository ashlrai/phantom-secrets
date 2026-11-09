import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  chmodSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

function extractFunction(source, name) {
  const start = source.indexOf(`${name}()`);
  assert.ok(start >= 0, `locate ${name}`);
  const lineEnd = source.indexOf('\n', start);
  if (source.slice(start, lineEnd).trimEnd().endsWith('}')) return source.slice(start, lineEnd + 1);
  const end = source.indexOf('\n}\n', start);
  assert.ok(end > start, `locate end of ${name}`);
  return source.slice(start, end + 3);
}

for (const file of ['scripts/install.sh', 'apps/web/public/install.sh']) {
  test(`${file} preserves the rc file when candidate creation fails`, (t) => {
    const root = mkdtempSync(join(tmpdir(), 'phantom-path-candidate-failure-'));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const home = join(root, 'home');
    const shims = join(root, 'shims');
    mkdirSync(home);
    mkdirSync(shims);
    const rc = join(home, '.bashrc');
    const original = Buffer.from('# existing configuration\nexport EXAMPLE=unchanged\n');
    writeFileSync(rc, original, { mode: 0o640 });
    const originalStat = statSync(rc);
    const realMktemp = execFileSync('which', ['mktemp'], { encoding: 'utf8' }).trim();
    writeFileSync(join(shims, 'mktemp'), `#!/bin/sh
case "$1" in
  */.phantom-path.candidate.*) : > "$PHANTOM_TEST_CANDIDATE_ATTEMPTED"; exit 1 ;;
esac
exec ${JSON.stringify(realMktemp)} "$@"
`);
    chmodSync(join(shims, 'mktemp'), 0o755);
    const source = readFileSync(resolve(import.meta.dirname, '..', file), 'utf8');
    const harness = ['set -euo pipefail',
      ...['say', 'file_identity', 'file_link_count', 'add_to_user_path']
        .map((name) => extractFunction(source, name)),
      'add_to_user_path "$1"',
    ].join('\n');
    const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', join(root, 'bin')], {
      cwd: root, encoding: 'utf8', timeout: 30000,
      env: { HOME: home, SHELL: '/bin/bash', PATH: `${shims}:/usr/bin:/bin`,
        PHANTOM_TEST_CANDIDATE_ATTEMPTED: join(root, 'attempted') },
    });
    assert.ifError(result.error);
    assert.equal(result.status, 1, 'PATH update reports failure');
    assert.equal(readFileSync(join(root, 'attempted'), 'utf8'), '', 'candidate creation was attempted');
    assert.deepEqual(readFileSync(rc), original, 'original rc bytes remain unchanged');
    assert.equal(statSync(rc).mode, originalStat.mode, 'original rc permissions remain unchanged');
    assert.equal(statSync(rc).ino, originalStat.ino, 'original rc file was not replaced');
    assert.deepEqual(readdirSync(home), ['.bashrc'], 'snapshot is cleaned up');
  });
}
