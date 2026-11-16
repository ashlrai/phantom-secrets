import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';

const workflow = readFileSync('.github/workflows/ci.yml', 'utf8');
for (const [tool, label, version] of [
  ['cargo-deny', 'Install verified cargo-deny', '0.20.2'],
  ['gitleaks', 'Install pinned Gitleaks', '8.30.0'],
]) {
  test(`${tool} verifies cache hits and downloads before saving`, () => {
    const root = mkdtempSync(join(tmpdir(), 'phantom-ci-test-'));
    try {
      const section = workflow.split(`      - name: Restore ${tool} archive\n`)[1].split('\n      - name:', 3);
      const restore = section[0];
      const install = section[1];
      const save = section[2];
      const prefix = tool === 'cargo-deny' ? 'CARGO_DENY' : 'GITLEAKS';
      const key = restore.match(/key: (.+)/)[1];
      const expectedKey = tool + '-${{ env.' + prefix + '_VERSION }}-${{ env.' + prefix + '_SHA256 }}';
      assert.equal(key, expectedKey);
      assert.match(workflow, new RegExp(`      ${prefix}_VERSION: ${version.replaceAll('.', '\\.')}\n      ${prefix}_SHA256: [a-f0-9]{64}\n`));
      assert.ok(save.includes(`key: ${key}`));
      assert.match(save, /actions\/cache\/save@[a-f0-9]{40}/);
      assert.match(install, /--retry 3 --retry-all-errors/);
      const script = install.split('        run: |\n')[1].replace(/^          /gm, '')
        .replaceAll('/tmp/phantom-tool-cache', join(root, 'cache'))
        .replaceAll(`/tmp/phantom-${tool}-bin`, join(root, 'install'));
      const src = join(root, 'src');
      const bin = join(root, 'bin');
      mkdirSync(src); mkdirSync(bin);
      const folder = tool === 'cargo-deny' ? `cargo-deny-${version}-x86_64-unknown-linux-musl/` : '';
      if (folder) mkdirSync(join(src, folder));
      const executable = join(src, folder, tool);
      writeFileSync(executable, '#!/bin/sh\nexit 0\n'); chmodSync(executable, 0o755);
      const fixture = join(root, 'fixture.tar.gz');
      execFileSync('tar', ['-czf', fixture, '-C', src, folder ? folder.slice(0, -1) : tool]);
      const digest = createHash('sha256').update(readFileSync(fixture)).digest('hex');
      writeFileSync(join(bin, 'curl'), '#!/bin/sh\nwhile [ "$1" != "--output" ]; do shift; done\ncp "$FIXTURE" "$2"\n');
      chmodSync(join(bin, 'curl'), 0o755);
      const env = { ...process.env, PATH: `${bin}:${process.env.PATH}`, FIXTURE: fixture,
        [`${prefix}_VERSION`]: version, [`${prefix}_SHA256`]: digest };
      const run = (extra) => spawnSync('bash', ['-c', script], { env: { ...env, ...extra }, encoding: 'utf8' });
      assert.equal(run({ CACHE_HIT: 'false' }).status, 0, 'cache miss downloads and verifies');
      const badDownload = run({ CACHE_HIT: 'false', [`${prefix}_SHA256`]: '0'.repeat(64) });
      assert.notEqual(badDownload.status, 0, 'wrong download checksum fails the install step');
      assert.match(badDownload.stdout + badDownload.stderr, /FAILED/);
      rmSync(fixture);
      assert.equal(run({ CACHE_HIT: 'true' }).status, 0, 'cache hit verifies without downloading');
      const badCacheHit = run({ CACHE_HIT: 'true', [`${prefix}_SHA256`]: '0'.repeat(64) });
      assert.notEqual(badCacheHit.status, 0, 'wrong cache checksum fails the install step');
      assert.match(badCacheHit.stdout + badCacheHit.stderr, /FAILED/);
      assert.ok(install.trimStart().startsWith(label));
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
}
