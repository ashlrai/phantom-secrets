import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { checkDocs, checkGuide, checkReadmeSurface, checkVersion, pageAnchors } from './check-docs-distribution.mjs';

test('reader guides agree on dated distribution evidence and local links exist', () => {
  assert.deepEqual(checkDocs(), []);
});
test('stale current claims fail even when the status link exists', () => {
  for (const claim of [
    'npm latest remains 0.6.0',
    'npm `latest` remains\n`0.6.0`',
    'npm `latest` is `0.6.0`',
    'formula still publishes v0.7.8',
    'formula currently at v0.7.8',
    'formula currently publishes `v0.7.8`',
    'formula at v0.7.8',
    'still `v0.7.8` until bumped',
    'it has not yet been bumped to the current `v0.7.9`',
    'prints `0.7.8` until the formula is bumped',
    'tap bump pending',
  ]) {
    assert.match(checkGuide(`distribution-status.md ${claim}`, 'README.md').join(), /stale/, claim);
  }
});
test('historical observations remain valid', () => {
  for (const text of [
    'distribution-status.md September snapshot: latest was 0.6.0',
    'distribution-status.md the formula published the previous reviewed `v0.7.8`',
    'distribution-status.md the tap was bumped from `v0.7.8` to `v0.7.9`',
    'distribution-status.md `v0.7.8` formula wrote the legacy entry; after upgrading, rerun setup',
    'distribution-status.md the Homebrew formula until it is bumped to `v0.7.9`',
  ]) {
    assert.deepEqual(checkGuide(text, 'README.md'), [], text);
  }
});
test('missing local links fail; external URLs and valid anchors pass', () => {
  const base = mkdtempSync(join(tmpdir(), 'phantom-doc-links-'));
  try {
    writeFileSync(join(base, 'distribution-status.md'), '## Tags\n');
    assert.deepEqual(checkGuide('# Here\n[status](distribution-status.md#tags) [web](https://example.com) [here](#here)', 'README.md', base), []);
    assert.match(checkGuide('distribution-status.md [broken](missing.md)', 'README.md', base).join(), /missing local link/);
  } finally { rmSync(base, { recursive: true, force: true }); }
});
test('same-page and cross-file anchors resolve', () => {
  const base = mkdtempSync(join(tmpdir(), 'phantom-doc-anchors-'));
  try {
    writeFileSync(join(base, 'distribution-status.md'), 'fixture');
    writeFileSync(join(base, 'target.md'), '## Real Heading\n');
    const ok = checkGuide('distribution-status.md\n# My Section\n[a](#my-section) [b](target.md#real-heading)', 'README.md', base);
    assert.deepEqual(ok, []);
    const bad = checkGuide('distribution-status.md\n[a](#missing) [b](target.md#nope)', 'README.md', base);
    assert.match(bad.join(), /missing anchor #missing/);
    assert.match(bad.join(), /missing anchor target\.md#nope/);
  } finally { rmSync(base, { recursive: true, force: true }); }
});
test('heading anchors dedupe like GitHub', () => {
  const anchors = pageAnchors('# Title\n## Repeat\n## Repeat\n', 'x.md');
  assert.ok(anchors.has('title') && anchors.has('repeat') && anchors.has('repeat-1'));
});
test('README surface rejects credential-shaped examples', () => {
  // Built in parts so this file carries no contiguous credential shape.
  const bad = checkReadmeSurface(['OPENAI_API_KEY=', 'sk-proj-', 'abc123def456'].join(''));
  assert.match(bad.join(), /credential-shaped/);
});
test('README surface requires every Ashlr sibling link', () => {
  const partial = '## Part of the Ashlr ecosystem\n[Phantom](https://phm.dev) x';
  assert.match(checkReadmeSurface(partial).join(), /ecosystem link https:\/\/github\.com\/ashlrai\/locus/);
});
test('missing status and release version drift fail', () => {
  assert.match(checkGuide('hello', 'README.md').join(), /missing distribution/);
  assert.equal(checkVersion('GitHub v0.0.0 assets latest: 0.7.9 release-candidate: 0.7.4').length, 1);
});


test('source candidates do not replace the published distribution receipt', () => {
  assert.deepEqual(checkVersion('GitHub v0.7.9 assets latest: 0.7.9 release-candidate: 0.7.4'), []);
  assert.equal(checkVersion('GitHub v0.8.0 assets latest: 0.7.9 release-candidate: 0.7.4').length, 1);
});
