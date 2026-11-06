import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const repo = resolve(import.meta.dirname, '..');

// `bash -n` parses without executing, so the check is safe on any host that
// has bash. Both checked-in Bash installers must stay parseable; the
// PowerShell copies are out of scope.
const installers = ['scripts/install.sh', 'apps/web/public/install.sh'];

function bashParse(path) {
  return spawnSync('/bin/bash', ['-n', path], { encoding: 'utf8' });
}

for (const rel of installers) {
  test(`${rel} parses under bash -n`, () => {
    const result = bashParse(join(repo, rel));
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
  });
}

// A syntax check is only worth keeping if it fails on broken input, so
// corrupt the real installer in a scratch copy and require bash -n to reject
// each corruption with a file:line diagnostic.
test('bash -n rejects corrupted installer copies', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'phantom-installer-syntax-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const source = readFileSync(join(repo, 'scripts/install.sh'), 'utf8');
  const copy = join(root, 'install.sh');
  const corruptions = [
    ['an unclosed if block', `${source}\nif [ -n "$PHANTOM_X" ]; then\n`],
    ['an unmatched quote', `${source}\necho "unclosed\n`],
    ['a stray done token', source.replace('\n', '\ndone\n')],
  ];
  for (const [label, text] of corruptions) {
    writeFileSync(copy, text);
    const result = bashParse(copy);
    assert.ifError(result.error);
    assert.notEqual(result.status, 0, `expected bash -n to reject ${label}`);
    assert.match(result.stderr, /syntax error|unexpected EOF|unexpected end of file/i, label);
    assert.match(result.stderr, /install\.sh: line \d+/, `${label}: diagnostic should name the file and line`);
  }
});
