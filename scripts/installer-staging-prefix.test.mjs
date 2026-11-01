import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');

test('staging prefix guide stays linked to the repository installer', () => {
  const source = read('scripts/install.sh');
  for (const fragment of [
    'INSTALL_DIR="${PHANTOM_INSTALL_DIR:-$HOME/.phantom-secrets/bin}"',
    'install_parent="$(dirname "$INSTALL_DIR")"',
    'install_name="$(basename "$INSTALL_DIR")"',
    'install_parent="$(cd "$install_parent" && pwd -P)"',
    'stage_root="$(mktemp -d "$install_parent/.${install_name}.install.XXXXXX")"',
  ]) assert.ok(source.includes(fragment), `review guide: installer changed ${fragment}`);
  const guide = read('docs/installer-staging-prefix.md');
  for (const term of [
    '<install_parent>/.<install_name>.install.XXXXXX',
    '/opt/phantom/.tools.install.XXXXXX', '.phantom-secrets/.bin.install.XXXXXX',
    'PHANTOM_INSTALL_DIR', 'pwd -P', 'TMPDIR', 'stage_root',
  ]) assert.ok(guide.includes(term), `guide must cover ${term}`);
  assert.match(read('docs/README.md'), /\]\(installer-staging-prefix\.md\)/);
});
