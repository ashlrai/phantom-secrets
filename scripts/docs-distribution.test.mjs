import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { checkDocs, checkGuide, checkVersion } from './check-docs-distribution.mjs';

test('reader guides agree on dated distribution evidence and local links exist', () => {
  assert.deepEqual(checkDocs(), []);
});
test('stale current claims fail even when the status link exists', () => {
  for (const claim of ['npm latest remains 0.6.0', 'npm `latest` remains\n`0.6.0`', 'formula still publishes v0.7.8', 'tap bump pending']) {
    assert.match(checkGuide(`distribution-status.md ${claim}`, 'README.md').join(), /stale/);
  }
});
test('historical observations remain valid', () => {
  assert.deepEqual(checkGuide('distribution-status.md September snapshot: latest was 0.6.0', 'README.md'), []);
});
test('missing local links fail; external URLs and same-page anchors are ignored', () => {
  const base = mkdtempSync(join(tmpdir(), 'phantom-doc-links-'));
  try {
    writeFileSync(join(base, 'distribution-status.md'), 'fixture');
    assert.deepEqual(checkGuide('[status](distribution-status.md#tags) [web](https://example.com) [here](#here)', 'README.md', base), []);
    assert.match(checkGuide('distribution-status.md [broken](missing.md)', 'README.md', base).join(), /missing local link/);
  } finally { rmSync(base, { recursive: true, force: true }); }
});
test('missing status and release version drift fail', () => {
  assert.match(checkGuide('hello', 'README.md').join(), /missing distribution/);
  assert.equal(checkVersion('GitHub v0.0.0 assets latest: 0.7.9 release-candidate: 0.7.4').length, 1);
});
