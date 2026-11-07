import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const files = ['scripts/install.sh', 'apps/web/public/install.sh'];
const sources = files.map((file) => readFileSync(new URL(`../${file}`, import.meta.url), 'utf8'));

// Same function boundary as installer-path-temp-failure.test.mjs: the
// PATH-update function ends where the installer's top-level checks begin.
function pathUpdateFunction(source, file) {
  const start = source.indexOf('add_to_user_path() {\n');
  const end = source.indexOf('\n}\n\ncommand -v curl', start);
  assert.ok(start >= 0 && end > start, `${file}: locate the installer PATH-update function`);
  return source.slice(start, end + '\n}'.length);
}

function pathTemplate(body, variable, file) {
  const creations = [...body.matchAll(
    new RegExp(`^\\s*${variable}="\\$\\(mktemp "([^"\\n]+)"\\)"`, 'gm'),
  )];
  assert.equal(creations.length, 1, `${file}: expected one ${variable} temporary-file creation`);
  return creations[0][1];
}

// The snapshot and replacement files must never share a template name: a
// shared name would make the second mktemp clobber the first file's role,
// and a swapped name would hide which file mv publishes.
function assertDistinctPathTemplates(source, file) {
  const body = pathUpdateFunction(source, file);
  const before = pathTemplate(body, 'before_tmp', file);
  const candidate = pathTemplate(body, 'candidate_tmp', file);
  assert.equal(before, '$rc_parent/.phantom-path.before.XXXXXX',
    `${file}: the before temporary file must keep the before name`);
  assert.equal(candidate, '$rc_parent/.phantom-path.candidate.XXXXXX',
    `${file}: the candidate temporary file must keep the candidate name`);
  assert.notEqual(before, candidate,
    `${file}: PATH-update temporary-file templates must use distinct names`);
}

for (const [index, file] of files.entries()) {
  test(`${file} PATH-update temporary-file templates use distinct before and candidate names`, () => {
    assertDistinctPathTemplates(sources[index], file);
  });
}

test('the distinct-name check rejects shared, swapped, and missing templates', () => {
  const source = sources[0];
  const shared = source.replace('.phantom-path.candidate.XXXXXX', '.phantom-path.before.XXXXXX');
  assert.throws(() => assertDistinctPathTemplates(shared, 'fixture'), /candidate name/);
  const swapped = source
    .replace('.phantom-path.before.XXXXXX', '.phantom-path.zzswap.XXXXXX')
    .replace('.phantom-path.candidate.XXXXXX', '.phantom-path.before.XXXXXX')
    .replace('.phantom-path.zzswap.XXXXXX', '.phantom-path.candidate.XXXXXX');
  assert.throws(() => assertDistinctPathTemplates(swapped, 'fixture'), /before name/);
  const missing = source.replace(
    'candidate_tmp="$(mktemp "$rc_parent/.phantom-path.candidate.XXXXXX")"',
    'candidate_tmp=""',
  );
  assert.throws(() => assertDistinctPathTemplates(missing, 'fixture'), /expected one/);
});
