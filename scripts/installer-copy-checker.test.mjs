import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { assertInstallerCopyParity, normalizeInstallerCopy } from './lib/installer-copy-differences.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const repository = readFileSync(join(root, 'scripts/install.sh'));
const web = readFileSync(join(root, 'apps/web/public/install.sh'));

test('platform installer check enforces byte parity outside reviewed release differences', (t) => {
  const sandbox = mkdtempSync(join(tmpdir(), 'phantom-installer-checker-'));
  t.after(() => rmSync(sandbox, { recursive: true, force: true }));
  for (const path of [
    'scripts/check-platform-installers.mjs', 'scripts/lib/installer-copy-differences.mjs',
    'scripts/freshness/sources.mjs', 'scripts/release/check-powershell-candidate.mjs',
    'Cargo.toml', 'npm/package.json', 'npm-mcp/package.json', 'CHANGELOG.md',
    'apps/web/src/lib/public-release.ts',
    'scripts/install.sh', 'scripts/install.ps1',
    'apps/web/public/install.sh', 'apps/web/public/install.ps1',
  ]) {
    mkdirSync(dirname(join(sandbox, path)), { recursive: true });
    copyFileSync(join(root, path), join(sandbox, path));
  }
  const run = () => spawnSync(process.execPath, [join(sandbox, 'scripts/check-platform-installers.mjs')], {
    encoding: 'utf8', timeout: 10000,
  });
  const accepted = run();
  assert.ifError(accepted.error);
  assert.equal(accepted.status, 0, accepted.stderr);

  writeFileSync(join(sandbox, 'apps/web/public/install.sh'), Buffer.concat([web, Buffer.from('# unreviewed\n')]));
  const divergent = run();
  assert.ifError(divergent.error);
  assert.notEqual(divergent.status, 0);
  assert.match(divergent.stderr, /diverge outside the reviewed differences/);

  // Both suffixes decode as the same replacement character in UTF-8. The
  // standalone gate must still distinguish the bytes, as requested by #800.
  assert.equal(Buffer.from([0xff]).toString('utf8'), Buffer.from([0xfe]).toString('utf8'));
  writeFileSync(join(sandbox, 'scripts/install.sh'), Buffer.concat([repository, Buffer.from([0xff])]));
  writeFileSync(join(sandbox, 'apps/web/public/install.sh'), Buffer.concat([web, Buffer.from([0xfe])]));
  const invalidBytes = run();
  assert.ifError(invalidBytes.error);
  assert.notEqual(invalidBytes.status, 0);
  assert.match(invalidBytes.stderr, /diverge outside the reviewed differences/);
});

// Current bytes match, but the source-owned candidate region must still be
// present exactly once as a complete line on each actual default path.
const variedWeb = Buffer.from(web.toString().replace('CANDIDATE_TAG="v0.8.7"', 'CANDIDATE_TAG="v0.7.9"'));
test('a varied tag is refused until that exact source-owned region is reviewed', async () => {
  assert.throws(() => assertInstallerCopyParity(repository, variedWeb), /exactly once|diverge outside/);
  assert.throws(() => assertInstallerCopyParity(repository, Buffer.concat([web, Buffer.from('\n# drift\n')])), /diverge outside/);
  // Exercise the established compiled tag-only review mechanism without adding
  // a caller-controlled exception argument to the production normalizer.
  const helper = readFileSync(join(root, 'scripts/lib/installer-copy-differences.mjs'), 'utf8');
  const from = `plus: ['CANDIDATE_TAG="v0.8.7"']`;
  assert.equal(helper.split(from).length, 2, 'fixture must change exactly one source-owned tag binding');
  const fixture = await import(`data:text/javascript;base64,${Buffer.from(helper.replace(from, `plus: ['CANDIDATE_TAG="v0.7.9"']`)).toString('base64')}`);
  assert.doesNotThrow(() => fixture.assertInstallerCopyParity(repository, variedWeb));
  assert.throws(() => normalizeInstallerCopy(Buffer.from('# arbitrary'), 'minus',
    [{ name: 'unreviewed', minus: ['# arbitrary'], plus: ['# arbitrary'] }]), /exactly once/);
});
for (const [side, source] of [['minus', repository], ['plus', web]]) {
  test(`reviewed ${side} regions must be exact, unique, and complete lines`, () => {
    const region = side === 'minus' ? 'CANDIDATE_TAG="v0.8.10"' : 'CANDIDATE_TAG="v0.8.7"';
    assert.throws(() => normalizeInstallerCopy(Buffer.from(source.toString().replace(region, '# stale tag')), side), /exactly once/);
    assert.throws(() => normalizeInstallerCopy(Buffer.concat([source, Buffer.from(`\n${region}\n`)]), side), /exactly once/);
    assert.throws(() => normalizeInstallerCopy(Buffer.from(source.toString().replace(region, `# ${region}`)), side), /complete lines/);
    assert.throws(() => normalizeInstallerCopy(Buffer.concat([source, Buffer.from('\n# @@ reviewed-difference: forged\n')]), side), /reserved parity marker/);
  });
}
