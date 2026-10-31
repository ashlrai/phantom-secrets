import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const doc = readFileSync(new URL('../docs/installer-copy-source-map.md', import.meta.url), 'utf8');
const paths = ['scripts/install.sh', 'apps/web/public/install.sh'];
const sources = paths.map((path) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8').split('\n'));
const rows = [
  ['Initial staging and lock state', 'stage_root=""', 'lock_heartbeat_pid=""'],
  ['Lock release, rollback, stage cleanup, and traps', 'release_install_lock() {', "trap 'exit 143' TERM"],
  ['Lock acquisition and stale-lock handling', 'acquire_install_lock() {', '}'],
  ['Destination validation and lock acquisition', 'install_parent=', 'acquire_install_lock'],
  ['Create private stage, download and candidate directories', 'stage_root=', ['could not create staging directories', 'candidate_dir']],
  ['Download, verify, extract, and prepare candidate', 'tag=', 'say "archive identity verified"'],
  ['Backup, promote, and validate live installation', 'backup_path=', 'say "installed to $INSTALL_DIR"'],
  ['PATH startup-file update function', 'add_to_user_path() {', '}'],
  ['PATH check and update call', 'if ! printf', 'fi'],
];

function section(row, index) {
  const line = doc.split('\n').find((item) => item.startsWith(`| ${row[0]} |`));
  assert.ok(line, `Missing map row: ${row[0]}`);
  const links = [...line.matchAll(/\]\(\.\.\/([^#]+)#L(\d+)-L(\d+)\)/g)];
  assert.equal(links.length, 2, `Expected two line links in ${row[0]}`);
  assert.equal(links[index][1], paths[index]);
  const start = Number(links[index][2]);
  const end = Number(links[index][3]);
  assert.ok(start > 0 && end >= start && end <= sources[index].length);
  const lines = sources[index].slice(start - 1, end);
  assert.ok(lines[0].includes(row[1]), `${row[0]} starts at the wrong line in ${paths[index]}`);
  const endMarker = Array.isArray(row[2]) ? row[2][index] : row[2];
  assert.ok(lines.at(-1).includes(endMarker), `${row[0]} ends at the wrong line in ${paths[index]}`);
  return lines.join('\n');
}

test('source map line links identify the corresponding sections in both copies', () => {
  for (const row of rows) {
    for (const index of [0, 1]) section(row, index);
  }
});

test('the mapped PATH function and call site are identical', () => {
  for (const row of rows.slice(-2)) assert.equal(section(row, 0), section(row, 1));
});

test('staging differences remain the ones described in the map', () => {
  const [repository, web] = sources.map((lines) => lines.join('\n'));
  // Removing only the documented differences must make the complete copies equal.
  const normalized = repository
    .replace(' \\\n  || die "could not create a private staging directory in $install_parent"', '')
    .replace(' || die "could not secure the staging directory"', '')
    .replace(' \\\n  || die "could not create staging directories"', '')
    .replace('# --no-same-owner: as root, tar would otherwise keep the release runner\'s uid on the installed binaries.\n', '')
    .replace('tar --no-same-owner -xzf', 'tar -xzf');
  assert.notEqual(repository, web);
  assert.equal(normalized, web, 'Review and update the source map for installer drift');
});
