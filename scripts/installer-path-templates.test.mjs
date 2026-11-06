import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const files = ['scripts/install.sh', 'apps/web/public/install.sh'];
const sources = files.map((file) => readFileSync(new URL(`../${file}`, import.meta.url), 'utf8'));

function pathTemplate(source, kind, file) {
  const start = source.indexOf('add_to_user_path() {\n');
  const end = source.indexOf('\n}\n', start);
  assert.ok(start >= 0 && end > start, `${file}: PATH-update function must exist`);
  const body = source.slice(start, end);
  const assignments = [...body.matchAll(new RegExp(`^\\s*${kind}_tmp=([^\\n]*)`, 'gm'))];
  assert.equal(assignments.length, 1, `${file}: expected one ${kind} temporary-file assignment`);
  const match = assignments[0][1].match(/^"\$\(mktemp "([^"\n]+)"\)"(?:\s|$)/);
  assert.ok(match, `${file}: ${kind} must use a quoted mktemp template`);
  return match[1];
}

for (const kind of ['before', 'candidate']) {
  test(`PATH-update ${kind} temporary-file templates match in both installers`, () => {
    const templates = sources.map((source, index) => pathTemplate(source, kind, files[index]));
    assert.equal(templates[0], templates[1], `${kind} templates must match across installers`);
    assert.equal(templates[0], `$rc_parent/.phantom-path.${kind}.XXXXXX`,
      `${kind} template must create a randomized sibling of the shell startup file`);
  });

  test(`PATH-update ${kind} template check rejects missing and duplicate assignments`, () => {
    const source = sources[0];
    const assignment = `${kind}_tmp="$(mktemp "$rc_parent/.phantom-path.${kind}.XXXXXX")"`;
    assert.ok(source.includes(assignment));
    assert.throws(() => pathTemplate(source.replace(assignment, ''), kind, files[0]), /expected one/);
    assert.throws(() => pathTemplate(source.replace(assignment, `${assignment}\n  ${assignment}`), kind, files[0]), /expected one/);
  });
}
