import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
const guide = read('docs/installer-temp-location-comparison.md');
const quickstart = read('apps/web/src/components/landing/QuickStart.tsx');
const installer = read('scripts/install.sh');

test('comparison tracks the two independent Unix staging paths and their contents', () => {
  const quickstartPatterns = [
    /mktemp -d "\\\$\{TMPDIR:-\/tmp\}\/phantom-install\.XXXXXX"/g,
    /phantom_installer="\$phantom_stage\/install\.sh"/g,
    /trap 'rm -f -- "\$phantom_installer"; rmdir -- "\$phantom_stage"/g,
  ];
  for (const pattern of quickstartPatterns) {
    assert.equal([...quickstart.matchAll(pattern)].length, 2, `review macOS and Linux commands: ${pattern}`);
  }
  for (const fragment of [
    'INSTALL_DIR="${PHANTOM_INSTALL_DIR:-$HOME/.phantom-secrets/bin}"',
    'install_parent="$(dirname "$INSTALL_DIR")"',
    'install_name="$(basename "$INSTALL_DIR")"',
    'install_parent="$(cd "$install_parent" && pwd -P)"',
    'stage_root="$(mktemp -d "$install_parent/.${install_name}.install.XXXXXX")"',
    'download_dir="$stage_root/download"',
    'candidate_dir="$stage_root/candidate"',
    'trap cleanup EXIT',
  ]) assert.ok(installer.includes(fragment), `review installer comparison: ${fragment}`);
  for (const term of [
    '${TMPDIR:-/tmp}/phantom-install.XXXXXX', '<install-parent>/.<install-name>.install.XXXXXX',
    'PHANTOM_INSTALL_DIR', 'download/', 'candidate/', 'pwd -P', 'pinned', 'best effort',
  ]) assert.ok(guide.includes(term), `comparison must explain ${term}`);
});

test('comparison and source links are discoverable and resolve', () => {
  assert.match(read('docs/README.md'), /\]\(installer-temp-location-comparison\.md\)/);
  for (const path of [
    'apps/web/src/components/landing/QuickStart.tsx', 'scripts/install.sh',
    'docs/installer-temp-environment.md', 'docs/installer-staging.md',
  ]) {
    const target = path.startsWith('docs/') ? path.slice(5) : `../${path}`;
    assert.ok(guide.includes(`](${target})`), `missing link to ${path}`);
    assert.ok(read(path).length > 0);
  }
});
