import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
const scriptDir = fileURLToPath(new URL('.', import.meta.url));

// A test file that is only committed never runs. Every installer offline test
// must therefore be named in a ci.yml `node --test` command; the suite grew to
// dozens of unreferenced files once before. installer-syntax.test.mjs is the
// one exception: it runs in its own cross-platform step instead of the
// Linux-only offline step.
const lexicalCompare = (a, b) => a < b ? -1 : a > b ? 1 : 0;
const suite = [
  ...readdirSync(scriptDir)
    .filter((f) => /^(?:installer-.+|installers|public-installer-.+)\.test\.(?:mjs|js)$/.test(f))
    .map((f) => `scripts/${f}`),
  'scripts/release/native-installer-acceptance.test.mjs',
].sort(lexicalCompare);
assert.ok(suite.length > 10, 'expected to discover the installer offline suite');

test('every installer offline test file is referenced by ci.yml', () => {
  const ci = read('.github/workflows/ci.yml');
  for (const file of suite) {
    assert.ok(ci.includes(file), `${file} has no node --test reference in ci.yml`);
  }
});

test('the offline installer step runs exactly the unwired-by-elsewhere suite', () => {
  const ci = read('.github/workflows/ci.yml');
  const step = ci.match(/- name: Run direct installer offline tests\n(?:.|\n)*?(?=^      - name:)/m);
  assert.ok(step, 'offline installer test step not found in ci.yml');
  const paths = [...step[0].matchAll(/scripts\/\S+\.test\.(?:mjs|js)/g)].map((m) => m[0]);
  assert.deepEqual(
    paths.sort(lexicalCompare),
    suite.filter((f) => f !== 'scripts/installer-syntax.test.mjs'),
    'offline installer step must list every installer test file except installer-syntax',
  );
});
