import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
const installers = ['scripts/install.sh', 'apps/web/public/install.sh'];

test('staging prefixes guide stays linked to both installer copies', () => {
  for (const file of installers) {
    const source = read(file);
    for (const fragment of [
      'INSTALL_DIR="${PHANTOM_INSTALL_DIR:-$HOME/.phantom-secrets/bin}"',
      'install_parent="$(dirname "$INSTALL_DIR")"',
      'install_name="$(basename "$INSTALL_DIR")"',
      'install_parent="$(cd "$install_parent" && pwd -P)"',
      'stage_root="$(mktemp -d "$install_parent/.${install_name}.install.XXXXXX")"',
      'lock_path="$install_parent/.${install_name}.install.lock"',
      'backup_path="$install_parent/.${install_name}.backup.${stage_root##*.}"',
    ]) assert.ok(source.includes(fragment), `review guide: ${file} changed ${fragment}`);
  }
  const guide = read('docs/installer-staging-prefixes.md');
  for (const term of [
    '<install_parent>/.<install_name>.install.XXXXXX',
    'apps/web/public/install.sh', 'scripts/install.sh',
    '.phantom-secrets/.bin.install.XXXXXX', '/opt/phantom/.tools.install.XXXXXX',
    '.install.lock', '.backup.', 'PHANTOM_INSTALL_DIR', 'pwd -P', 'TMPDIR',
    'stage_root', 'install_parent', 'install_name',
  ]) assert.ok(guide.includes(term), `guide must cover ${term}`);
  assert.match(read('docs/README.md'), /\]\(installer-staging-prefixes\.md\)/);
});
