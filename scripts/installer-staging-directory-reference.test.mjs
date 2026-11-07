import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');

test('staging directory reference tracks the repository installer', () => {
  const source = read('scripts/install.sh');
  for (const fragment of [
    'INSTALL_DIR="${PHANTOM_INSTALL_DIR:-$HOME/.phantom-secrets/bin}"',
    'install_parent="$(dirname "$INSTALL_DIR")"',
    'install_name="$(basename "$INSTALL_DIR")"',
    'install_parent="$(cd "$install_parent" && pwd -P)"',
    'stage_root="$(mktemp -d "$install_parent/.${install_name}.install.XXXXXX")"',
    'chmod 700 "$stage_root"',
    'mkdir -m 700 "$download_dir" "$candidate_dir"',
    'rm -rf -- "$stage_root"',
  ]) assert.ok(source.includes(fragment), `review reference: installer changed ${fragment}`);

  const doc = read('docs/installer-staging-directory-reference.md');
  for (const fragment of [
    '<install_parent>/.<install_name>.install.XXXXXX',
    '$HOME/.phantom-secrets/.bin.install.XXXXXX',
    '/opt/phantom/.tools.install.XXXXXX',
    'PHANTOM_INSTALL_DIR', 'dirname', 'basename', 'pwd -P', 'TMPDIR',
    'stage_root', 'download', 'candidate', 'mode 700',
    '../scripts/install.sh', 'installer-staging-review.md',
  ]) assert.ok(doc.includes(fragment), `reference must cover ${fragment}`);
  assert.match(read('docs/README.md'), /\]\(installer-staging-directory-reference\.md\)/);
});
