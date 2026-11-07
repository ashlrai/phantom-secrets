import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const repositoryCopy = 'scripts/install.sh';
const webCopy = 'apps/web/public/install.sh';
const [repository, web] = [repositoryCopy, webCopy].map((file) =>
  readFileSync(new URL(`../${file}`, import.meta.url)),
);

// Index of the first byte where two buffers differ, or -1 when they are
// byte-identical. A length-only difference reports the first index past the
// shorter buffer, so truncation and padding both count as mismatches.
function firstMismatch(a, b) {
  const limit = Math.min(a.length, b.length);
  for (let index = 0; index < limit; index += 1) {
    if (a[index] !== b[index]) return index;
  }
  return a.length === b.length ? -1 : limit;
}

// 1-based line number containing a byte offset.
function lineOf(buffer, offset) {
  let line = 1;
  for (let index = 0; index < offset; index += 1) {
    if (buffer[index] === 0x0a) line += 1;
  }
  return line;
}

function byteComparison() {
  const result = spawnSync('cmp', [repositoryCopy, webCopy], { cwd: root, encoding: 'utf8' });
  assert.ifError(result.error);
  assert.ok(result.status === 0 || result.status === 1, `cmp failed (exit ${result.status}): ${result.stderr}`);
  return result;
}

// GNU cmp calls this a byte; BSD cmp calls the same 1-based offset a char.
function parseComparisonReport(report) {
  const match = /^scripts\/install\.sh apps\/web\/public\/install\.sh differ: (?:byte|char) ([1-9]\d*), line ([1-9]\d*)$/.exec(report);
  return match ? { byte: Number(match[1]), line: Number(match[2]) } : null;
}

test('cmp report parser accepts only the two complete mismatch formats', () => {
  for (const unit of ['byte', 'char']) {
    assert.deepEqual(parseComparisonReport(`scripts/install.sh apps/web/public/install.sh differ: ${unit} 730, line 19`), { byte: 730, line: 19 });
  }
  for (const report of [
    'other/install.sh apps/web/public/install.sh differ: byte 730, line 19',
    'scripts/install.sh apps/web/public/install.sh differ: bytes 730, line 19',
    'scripts/install.sh apps/web/public/install.sh differ: byte 0, line 19',
    'scripts/install.sh apps/web/public/install.sh differ: char 730, line 19 extra',
    'scripts/install.sh apps/web/public/install.sh are identical',
  ]) assert.equal(parseComparisonReport(report), null);
});

test('byte-for-byte comparison reports the reviewed mismatch', (t) => {
  // The web copy is byte-bound to separately reviewed release bytes, so the
  // reviewed state is a mismatch; docs/installer-copy-comparison.md pins the
  // SHA-256 of each copy. A byte-for-byte comparison must report that
  // mismatch: byte-identical copies mean the review record is stale.
  assert.ok(
    !repository.equals(web),
    `${repositoryCopy} and ${webCopy} are byte-identical; ` +
      'refresh the copy review in docs/installer-copy-comparison.md',
  );

  const result = byteComparison();
  assert.equal(result.status, 1, `cmp should report a mismatch: ${result.stderr.trim()}`);
  const report = result.stdout.trim();
  assert.ok(parseComparisonReport(report), 'cmp must report the mismatch location');
  t.diagnostic(`byte-for-byte comparison reports a mismatch: ${report}`);
});

test('an in-process byte scan reports the same mismatch location', (t) => {
  const offset = firstMismatch(repository, web);
  assert.notEqual(offset, -1, 'the byte scan must report a mismatch');
  const [char, line] = [offset + 1, lineOf(repository, offset)];
  t.diagnostic(`first differing byte: char ${char}, line ${line}`);

  // The scan must agree with cmp's own mismatch report.
  const reported = parseComparisonReport(byteComparison().stdout.trim());
  assert.ok(reported, 'cmp must report the mismatch location');
  assert.equal(reported.byte, char);
  assert.equal(reported.line, line);

  // The first divergence is the reviewed candidate-tag difference at line 19
  // (docs/installer-copy-source-map.md); an earlier byte means unreviewed
  // drift that the approved-difference list cannot explain.
  assert.equal(line, 19, `first mismatch moved to line ${line}; re-review the installer copies`);
});

test('the byte scan reports no mismatch for equal inputs', () => {
  assert.equal(firstMismatch(repository, repository), -1);
  const offset = firstMismatch(repository, web);
  assert.ok(offset > 0);
  assert.equal(firstMismatch(repository.subarray(0, offset), web.subarray(0, offset)), -1);
  assert.equal(firstMismatch(repository.subarray(0, offset + 1), web.subarray(0, offset + 1)), offset);
});
