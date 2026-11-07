import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { approvedDifferences, repositoryCopy, webCopy } from './lib/installer-copy-differences.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
// Keep the diff-group checks as well as the byte-preserving platform gate.

function installerDiff(contextLines) {
  const result = spawnSync('diff', [`-U${contextLines}`, repositoryCopy, webCopy], { cwd: root, encoding: 'utf8' });
  assert.ifError(result.error);
  assert.ok(result.status === 0 || result.status === 1, `diff failed (exit ${result.status}): ${result.stderr}`);
  return result.stdout;
}

function changeGroups(diffOutput) {
  const groups = [];
  for (const line of diffOutput.split('\n')) {
    if (line.startsWith('@@ ')) groups.push({ minus: [], plus: [] });
    else if (groups.length && line.startsWith('-')) groups.at(-1).minus.push(line.slice(1));
    else if (groups.length && line.startsWith('+')) groups.at(-1).plus.push(line.slice(1));
  }
  return groups;
}

test('installer copies differ only by the reviewed changes', () => {
  const pending = changeGroups(installerDiff(0)).map((group) => JSON.stringify([group.minus, group.plus]));
  const missing = approvedDifferences.filter((entry) => {
    const index = pending.indexOf(JSON.stringify([entry.minus, entry.plus]));
    if (index < 0) return true;
    pending.splice(index, 1);
    return false;
  });

  const failures = [];
  if (pending.length) {
    failures.push(
      `${repositoryCopy} and ${webCopy} differ in unreviewed ways; re-review the copies ` +
      `and update the approved differences (see docs/installer-copy-comparison.md):\n${installerDiff(3)}`,
    );
  }
  if (missing.length) {
    failures.push(
      `Reviewed differences are no longer present; refresh the approved differences and the review docs:\n` +
      missing.map((entry) => `- ${entry.name}`).join('\n'),
    );
  }
  if (failures.length) assert.fail(failures.join('\n\n'));
});

test('approved differences remain anchored in both installer copies', () => {
  const repository = readFileSync(new URL(`../${repositoryCopy}`, import.meta.url), 'utf8');
  const web = readFileSync(new URL(`../${webCopy}`, import.meta.url), 'utf8');
  for (const entry of approvedDifferences) {
    assert.ok(
      repository.includes(entry.minus.join('\n')),
      `"${entry.name}" is not present verbatim in ${repositoryCopy}; refresh the approved differences`,
    );
    assert.ok(
      web.includes(entry.plus.join('\n')),
      `"${entry.name}" is not present verbatim in ${webCopy}; refresh the approved differences`,
    );
  }
});
