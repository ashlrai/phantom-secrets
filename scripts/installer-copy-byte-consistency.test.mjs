import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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

function byteComparison(cwd = root) {
  const result = spawnSync('cmp', [repositoryCopy, webCopy], { cwd, encoding: 'utf8' });
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

test('byte-for-byte comparison confirms current copies match', () => {
  assert.ok(repository.equals(web), 'refresh the copy review when current bytes differ');
  const result = byteComparison();
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, '');
  assert.equal(firstMismatch(repository, web), -1);
});

test('synthetic tag mismatch location agrees with cmp and detects earlier drift', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'phantom-cmp-pair-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  mkdirSync(join(directory, 'scripts'), { recursive: true });
  mkdirSync(join(directory, 'apps/web/public'), { recursive: true });
  const source = repository.toString('latin1');
  const currentTag = 'CANDIDATE_TAG="v0.8.7"';
  assert.equal(source.split(currentTag).length, 2, 'candidate tag must occur exactly once');
  const varied = Buffer.from(source.replace(currentTag, 'CANDIDATE_TAG="v0.7.9"'), 'latin1');
  writeFileSync(join(directory, repositoryCopy), repository);
  writeFileSync(join(directory, webCopy), varied);

  const offset = firstMismatch(repository, varied);
  assert.ok(offset > 0);
  const report = byteComparison(directory);
  assert.equal(report.status, 1);
  const reported = parseComparisonReport(report.stdout.trim());
  assert.ok(reported, 'cmp must report the mismatch location');
  assert.equal(reported.byte, offset + 1);
  assert.equal(reported.line, lineOf(repository, offset));
  assert.equal(reported.line, 19, 'synthetic tag mismatch should be at the candidate line');
  assert.equal(firstMismatch(repository.subarray(0, offset), varied.subarray(0, offset)), -1);
  assert.equal(firstMismatch(repository.subarray(0, offset + 1), varied.subarray(0, offset + 1)), offset);

  const drift = Buffer.from(varied);
  drift[0] ^= 1;
  writeFileSync(join(directory, webCopy), drift);
  const earlier = byteComparison(directory);
  assert.equal(earlier.status, 1);
  assert.deepEqual(parseComparisonReport(earlier.stdout.trim()), { byte: 1, line: 1 });
  assert.equal(firstMismatch(repository, drift), 0);
});

test('byte scan detects truncation and padding as well as equality', () => {
  assert.equal(firstMismatch(repository, repository), -1);
  assert.equal(firstMismatch(repository, repository.subarray(0, -1)), repository.length - 1);
  assert.equal(firstMismatch(repository, Buffer.concat([repository, Buffer.from([0])])), repository.length);
});
