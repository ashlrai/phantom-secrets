import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
const source = read('scripts/install.sh');
const doc = read('docs/installer-stage-parent.md');

test('stage parent documentation tracks the installer template and derivation', () => {
  for (const fragment of [
    'INSTALL_DIR="${PHANTOM_INSTALL_DIR:-$HOME/.phantom-secrets/bin}"',
    'install_parent="$(dirname "$INSTALL_DIR")"',
    'install_name="$(basename "$INSTALL_DIR")"',
    'install_parent="$(cd "$install_parent" && pwd -P)"',
    'stage_root="$(mktemp -d "$install_parent/.${install_name}.install.XXXXXX")"',
  ]) assert.ok(source.includes(fragment), `review documentation: installer changed ${fragment}`);
  for (const term of [
    '<install_parent>/.<install_name>.install.XXXXXX', 'install_parent',
    'install_name', 'stage_root', 'PHANTOM_INSTALL_DIR', 'TMPDIR', 'pwd -P',
  ]) assert.ok(doc.includes(term), `documentation must cover ${term}`);
  assert.match(read('docs/README.md'), /\]\(installer-stage-parent\.md\)/);
});
