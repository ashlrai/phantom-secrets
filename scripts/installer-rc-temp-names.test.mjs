import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
const installer = read('scripts/install.sh');
const doc = read('docs/installer-rc-temp-names.md');

test('RC temporary templates and their parent match the installer', () => {
  const functionBody = installer.match(/add_to_user_path\(\) \{([\s\S]*?)\n\}/)?.[1];
  assert.ok(functionBody, 'PATH update function must exist');
  const templates = [...functionBody.matchAll(/(\w+)=\"\$\(mktemp \"([^\"]+)\"\)\"/g)]
    .map(([, variable, template]) => [variable, template]);
  assert.deepEqual(templates, [
    ['before_tmp', '$rc_parent/.phantom-path.before.XXXXXX'],
    ['candidate_tmp', '$rc_parent/.phantom-path.candidate.XXXXXX'],
  ]);
  for (const [variable, template] of templates) {
    assert.ok(doc.includes(`| \`${variable}\` | \`${template}\` |`));
  }
  assert.match(functionBody, /rc_parent="\$\(dirname "\$rc"\)"/);
  assert.match(functionBody, /rc_parent="\$\(cd "\$rc_parent" && pwd -P\)"/);
  assert.match(functionBody, /zsh\)\s+rc="\$HOME\/\.zshrc"/);
  assert.match(functionBody, /fish\)\s+rc="\$HOME\/\.config\/fish\/config\.fish"/);
  assert.match(functionBody, /\*\)\s+rc="\$HOME\/\.bashrc"/);
  assert.match(read('docs/README.md'), /\]\(installer-rc-temp-names\.md\)/);
});
