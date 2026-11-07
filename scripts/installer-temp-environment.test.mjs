import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
const doc = read('docs/installer-temp-environment.md');
const pathReference = read('docs/installer-path-update-reference.md');
const installer = read('scripts/install.sh');
const quickstart = read('apps/web/src/components/landing/QuickStart.tsx');

test('documented temporary locations remain tied to their source templates', () => {
  const pairs = [
    ['${TMPDIR:-/tmp}', /\\\$\{TMPDIR:-\/tmp\}\/phantom-install\.XXXXXX/g, quickstart, 2],
    ['$env:TEMP', /Join-Path \$env:TEMP \('phantom-install-\$\{PUBLIC_RELEASE_TAG\}-\{0\}\.ps1'/g, quickstart, 1],
    ['PHANTOM_INSTALL_DIR', /INSTALL_DIR="\$\{PHANTOM_INSTALL_DIR:-\$HOME\/\.phantom-secrets\/bin\}"/g, installer, 1],
    ['.<install-name>.install.XXXXXX', /mktemp -d "\$install_parent\/\.\$\{install_name\}\.install\.XXXXXX"/g, installer, 1],
    ['.<install-name>.backup.<stage-suffix>', /backup_path="\$install_parent\/\.\$\{install_name\}\.backup\.\$\{stage_root##\*\.\}"/g, installer, 1],
    ['.<install-name>.install.lock', /lock_path="\$install_parent\/\.\$\{install_name\}\.install\.lock"/g, installer, 1],
    ['.phantom-path.before.XXXXXX', /mktemp "\$rc_parent\/\.phantom-path\.before\.XXXXXX"/g, installer, 1],
    ['.phantom-path.candidate.XXXXXX', /mktemp "\$rc_parent\/\.phantom-path\.candidate\.XXXXXX"/g, installer, 1],
  ];
  for (const [term, sourcePattern, source, count] of pairs) {
    assert.ok(doc.includes(term), `document must cover ${term}`);
    assert.equal([...source.matchAll(sourcePattern)].length, count, `review documentation for ${term}`);
  }
});

test('PATH update reference identifies both temporary siblings and their source', () => {
  assert.match(read('docs/README.md'), /\]\(installer-path-update-reference\.md\)/);
  for (const name of ['before', 'candidate']) {
    assert.ok(pathReference.includes(`.phantom-path.${name}.XXXXXX`));
    assert.ok(installer.includes(`mktemp "$rc_parent/.phantom-path.${name}.XXXXXX"`));
  }
  assert.match(pathReference, /exit trap/);
  const links = [...pathReference.matchAll(/\]\(\.\.\/scripts\/install\.sh#L(\d+)(?:-L(\d+))?\)/g)];
  assert.ok(links.length >= 4);
  const lines = installer.split('\n');
  for (const [, first, last = first] of links) {
    assert.ok(+first > 0 && +last >= +first && +last <= lines.length);
    assert.ok(lines.slice(+first - 1, +last).some((line) => line.trim()));
  }
});

test('source citations resolve to real nonempty line ranges', () => {
  assert.match(read('docs/README.md'), /\]\(installer-temp-environment\.md\)/);
  const links = [...doc.matchAll(/\]\(\.\.\/([^()#]+)#L(\d+)(?:-L(\d+))?\)/g)];
  assert.ok(links.some(([, path]) => path === 'scripts/install.sh'));
  assert.ok(links.some(([, path]) => path === 'apps/web/src/components/landing/QuickStart.tsx'));
  for (const [, path, first, last = first] of links) {
    const lines = read(path).split('\n');
    assert.ok(+first > 0 && +last >= +first && +last <= lines.length, `invalid citation ${path}:${first}-${last}`);
    assert.ok(lines.slice(+first - 1, +last).some((line) => line.trim()), `empty citation ${path}:${first}-${last}`);
  }
});
