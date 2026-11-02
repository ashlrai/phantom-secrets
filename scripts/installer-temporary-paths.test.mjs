import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
const installers = ['scripts/install.sh', 'apps/web/public/install.sh'];

test('temporary-path reference tracks both Unix installers', () => {
  const doc = read('docs/installer-temporary-paths.md');
  for (const file of installers) {
    assert.ok(doc.includes(`](../${file})`), `reference must link ${file}`);
    const source = read(file);
    for (const fragment of [
      'INSTALL_DIR="${PHANTOM_INSTALL_DIR:-$HOME/.phantom-secrets/bin}"',
      'install_parent="$(cd "$install_parent" && pwd -P)"',
      'stage_root="$(mktemp -d "$install_parent/.${install_name}.install.XXXXXX")"',
      'download_dir="$stage_root/download"',
      'candidate_dir="$stage_root/candidate"',
      'rc_parent="$(cd "$rc_parent" && pwd -P)"',
      'before_tmp="$(mktemp "$rc_parent/.phantom-path.before.XXXXXX")"',
      'candidate_tmp="$(mktemp "$rc_parent/.phantom-path.candidate.XXXXXX")"',
    ]) assert.ok(source.includes(fragment), `${file}: review changed path behavior: ${fragment}`);
  }
  for (const fragment of [
    '<resolved install parent>/.<install directory name>.install.XXXXXX/',
    '$HOME/.phantom-secrets/.bin.install.XXXXXX/',
    '.phantom-path.before.XXXXXX', '.phantom-path.candidate.XXXXXX',
    'PHANTOM_INSTALL_DIR', 'TMPDIR', 'pwd -P', 'exit trap',
    'installer-staging-directory-reference.md', 'installer-path-update-reference.md',
  ]) assert.ok(doc.includes(fragment), `reference must cover ${fragment}`);
  assert.match(read('docs/README.md'), /\]\(installer-temporary-paths\.md\)/);
});
