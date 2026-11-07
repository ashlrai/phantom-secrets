import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
const copies = { 'scripts/install.sh': read('scripts/install.sh'), 'apps/web/public/install.sh': read('apps/web/public/install.sh') };

// Every non-comment line that mentions TMPDIR, normalized for whitespace.
const tmpdirLines = (src) =>
  src.split('\n').filter((l) => /TMPDIR/.test(l) && !/^\s*#/.test(l)).map((l) => l.trim());

test('both installer copies use the same TMPDIR references and fallback', () => {
  const [a, b] = Object.values(copies).map(tmpdirLines);
  assert.deepEqual(a, b, 'TMPDIR usage must match between installer copies');
  for (const line of a) {
    for (const m of line.matchAll(/\$\{?TMPDIR(?::?-([^}]*))?\}?/g)) {
      assert.equal(m[1], '/tmp', `TMPDIR must fall back to /tmp, got: ${line}`);
    }
  }
});

test('every mktemp call in both copies uses an explicit private parent template', () => {
  for (const [name, src] of Object.entries(copies)) {
    const calls = src.split('\n').filter((l) => /\bmktemp\b/.test(l) && !/^\s*#/.test(l));
    assert.ok(calls.length > 0, `${name} should create temporary paths`);
    for (const line of calls) {
      assert.match(line, /mktemp (-d )?"\$(install_parent|rc_parent)\/\./, `${name}: bare mktemp would fall back to ambient TMPDIR: ${line.trim()}`);
    }
  }
});
