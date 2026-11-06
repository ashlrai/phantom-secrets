import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { normalizeInstallerCopy, repositoryCopy, webCopy } from './lib/installer-copy-differences.mjs';

const copies = { minus: repositoryCopy, plus: webCopy };

// Outside the reviewed differences pinned in
// lib/installer-copy-differences.mjs, the repository installer and the
// web-served copy must stay identical. Replacing each reviewed region with a
// placeholder in its own copy leaves bytes that must match exactly; any other
// added, removed, or reworded line is unreviewed divergence and fails here.
function diffNormalized(repository, web) {
  const directory = mkdtempSync(join(tmpdir(), 'phantom-installer-parity-'));
  try {
    const left = join(directory, 'repository.normalized');
    const right = join(directory, 'web.normalized');
    writeFileSync(left, repository);
    writeFileSync(right, web);
    const result = spawnSync('diff', ['-u', '--label', repositoryCopy, '--label', webCopy, left, right], { encoding: 'utf8' });
    return result.status === 1 ? result.stdout : result.stderr;
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test('installer copies are identical outside the reviewed differences', () => {
  const sources = Object.fromEntries(
    Object.entries(copies).map(([side, path]) => [
      side,
      readFileSync(new URL(`../${path}`, import.meta.url)),
    ]),
  );
  const repository = normalizeInstallerCopy(sources.minus, 'minus');
  const web = normalizeInstallerCopy(sources.plus, 'plus');
  assert.ok(
    repository.equals(web),
    `${repositoryCopy} and ${webCopy} diverge outside the reviewed differences; ` +
    're-review the copies and update lib/installer-copy-differences.mjs ' +
    '(see docs/installer-copy-comparison.md):\n' + diffNormalized(repository, web),
  );
});
