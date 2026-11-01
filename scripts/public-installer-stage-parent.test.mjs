import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');

test('public stage parent guide identifies the installer template and its source', () => {
  const doc = read('docs/public-installer-stage-parent.md');
  const source = read('apps/web/public/install.sh');
  assert.match(read('docs/README.md'), /\]\(public-installer-stage-parent\.md\)/);
  assert.ok(doc.includes('<install-parent>/.<install-name>.install.XXXXXX'));
  assert.ok(doc.includes('`install_parent`'));
  assert.ok(doc.includes('not under `TMPDIR`'));
  assert.match(source, /install_parent="\$\(dirname "\$INSTALL_DIR"\)"/);
  assert.match(source, /install_parent="\$\(cd "\$install_parent" && pwd -P\)"/);
  assert.match(source, /stage_root="\$\(mktemp -d "\$install_parent\/\.\$\{install_name\}\.install\.XXXXXX"\)"/);
  const links = [...doc.matchAll(/\]\(\.\.\/apps\/web\/public\/install\.sh#L(\d+)(?:-L(\d+))?\)/g)];
  assert.ok(links.length >= 4);
  const lines = source.split('\n');
  for (const [, first, last = first] of links) {
    assert.ok(+first > 0 && +last >= +first && +last <= lines.length);
    assert.ok(lines.slice(+first - 1, +last).some((line) => line.trim()));
  }
});
