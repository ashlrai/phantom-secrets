import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const installers = [
  ['scripts/install.sh', true],
  ['apps/web/public/install.sh', true],
];

// Both copies use explicit die guards on top of errexit. Pin the guarded form
// at top level between the lock and the release setup, so a failed creation
// cannot fall through to a download.
function assertStagingContract(source, guarded) {
  const lines = source.split('\n');
  assert.deepEqual(lines.filter((line) => /^\s*set\s/.test(line)), ['set -euo pipefail']);
  assert.equal(lines.filter((line) => line === 'trap cleanup EXIT').length, 1);
  if (guarded) {
    assert.equal(lines.filter((line) => /^die\(\)/.test(line)).length, 1);
    assert.match(source, /^die\(\)  \{ .*; exit 1; \}$/m);
  }
  assert.match(source, /cleanup\(\) \{\n  local rc=\$\?[\s\S]*?\n  if \[ -n "\$stage_root" \] && \[ -d "\$stage_root" \]; then\n    rm -rf -- "\$stage_root"\n  fi\n  release_install_lock\n  exit "\$rc"\n\}\ntrap cleanup EXIT/);

  const stage = [
    'acquire_install_lock',
    '',
    'stage_root="$(mktemp -d "$install_parent/.${install_name}.install.XXXXXX")"' +
      (guarded ? ' \\' : ''),
    ...(guarded ? ['  || die "could not create a private staging directory in $install_parent"'] : []),
    'chmod 700 "$stage_root"' + (guarded ? ' || die "could not secure the staging directory"' : ''),
    'download_dir="$stage_root/download"',
    'candidate_dir="$stage_root/candidate"',
    'mkdir -m 700 "$download_dir" "$candidate_dir"' + (guarded ? ' \\' : ''),
    ...(guarded ? ['  || die "could not create staging directories"'] : []),
    '',
    'tag="$PIN_TAG"',
  ].join('\n');
  assert.equal(source.split(stage).length - 1, 1, 'expected one unmodified staging block');
  assert.ok(source.indexOf('set -euo pipefail') < source.indexOf(stage));
  assert.ok(source.indexOf('trap cleanup EXIT') < source.indexOf(stage));
}

for (const [path, guarded] of installers) {
  test(`${path} keeps fail-closed staging creation and cleanup`, () => {
    assertStagingContract(readFileSync(new URL(`../${path}`, import.meta.url), 'utf8'), guarded);
  });
}

test('the staging contract rejects lost guards, errexit, and cleanup', () => {
  const repository = readFileSync(new URL('../scripts/install.sh', import.meta.url), 'utf8');
  const web = readFileSync(new URL('../apps/web/public/install.sh', import.meta.url), 'utf8');
  for (const diagnostic of [
    'could not create a private staging directory in $install_parent',
    'could not secure the staging directory',
    'could not create staging directories',
  ]) {
    assert.throws(() => assertStagingContract(repository.replace(diagnostic, 'ignored'), true));
  }
  assert.throws(() => assertStagingContract(repository.replace('; exit 1; }', '; exit 0; }'), true));
  assert.throws(() => assertStagingContract(web.replace('set -euo pipefail', 'set -uo pipefail'), true));
  assert.throws(() => assertStagingContract(web.replace('acquire_install_lock\n\n', 'acquire_install_lock\nset +e\n\n'), true));
  assert.throws(() => assertStagingContract(web.replace('trap cleanup EXIT', 'trap : EXIT'), true));
  assert.throws(() => assertStagingContract(web.replace('chmod 700 "$stage_root"', 'chmod 700 "$stage_root" || true'), true));
});
