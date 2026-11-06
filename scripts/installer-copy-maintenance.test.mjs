import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
const copies = ['scripts/install.sh', 'apps/web/public/install.sh'];
const guide = read('docs/installer-copy-maintenance.md');

test('maintenance guide records staging and PATH temporary templates from both copies', () => {
  const blocks = [...guide.matchAll(/```text\n([\s\S]*?)\n\s*```/g)].map((match) => match[1]);
  assert.equal(blocks.length, 2, 'expected staging and PATH template blocks');
  const documented = blocks.flatMap((block) => block.split('\n').map((line) => line.trim()));
  assert.equal(documented.length, 3, 'expected one staging and two PATH templates');

  for (const path of copies) {
    const source = read(path);
    const templates = [...source.matchAll(/mktemp(?: -d)? "(\$(?:install_parent|rc_parent)\/[^"\n]+)"/g)]
      .map((match) => match[1]);
    assert.deepEqual(templates.sort(), [...documented].sort(), `review ${path} and the maintenance guide`);
    assert.ok(guide.includes(`](../${path})`), `guide must link to ${path}`);
  }
  assert.match(read('docs/README.md'), /\]\(installer-copy-maintenance\.md\)/);
});
