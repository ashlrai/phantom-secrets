import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const repositoryCopy = 'scripts/install.sh';
const webCopy = 'apps/web/public/install.sh';

// Reviewed differences between the repository installer and the web-served
// copy; docs/installer-copy-comparison.md carries the prose record. Each entry
// pins one changed region exactly: `minus` lines exist only in the repository
// copy and `plus` lines replace them in the web copy. Any drift beyond this
// list — an added, removed, or reworded line — fails the consistency check.
const approvedDifferences = [
  {
    name: 'staging directory creation and permission changes keep die() guards only in the repository copy',
    minus: [
      'stage_root="$(mktemp -d "$install_parent/.${install_name}.install.XXXXXX")" \\',
      '  || die "could not create a private staging directory in $install_parent"',
      'chmod 700 "$stage_root" || die "could not secure the staging directory"',
    ],
    plus: [
      'stage_root="$(mktemp -d "$install_parent/.${install_name}.install.XXXXXX")"',
      'chmod 700 "$stage_root"',
    ],
  },
  {
    name: 'staging subdirectory creation keeps a die() guard only in the repository copy',
    minus: [
      'mkdir -m 700 "$download_dir" "$candidate_dir" \\',
      '  || die "could not create staging directories"',
    ],
    plus: ['mkdir -m 700 "$download_dir" "$candidate_dir"'],
  },
  {
    name: 'the repository copy extracts the release archive with tar --no-same-owner',
    minus: [
      "# --no-same-owner: as root, tar would otherwise keep the release runner's uid on the installed binaries.",
      'tar --no-same-owner -xzf "$archive_path" -C "$candidate_dir" || die "could not extract release archive"',
    ],
    plus: [
      'tar -xzf "$archive_path" -C "$candidate_dir" || die "could not extract release archive"',
    ],
  },
];

function installerDiff(contextLines) {
  const result = spawnSync('diff', [`-U${contextLines}`, repositoryCopy, webCopy], { cwd: root, encoding: 'utf8' });
  assert.ifError(result.error);
  assert.ok(result.status === 0 || result.status === 1, `diff failed (exit ${result.status}): ${result.stderr}`);
  return result.stdout;
}

function changeGroups(diffOutput) {
  const groups = [];
  for (const line of diffOutput.split('\n')) {
    if (line.startsWith('@@ ')) groups.push({ minus: [], plus: [] });
    else if (groups.length && line.startsWith('-')) groups.at(-1).minus.push(line.slice(1));
    else if (groups.length && line.startsWith('+')) groups.at(-1).plus.push(line.slice(1));
  }
  return groups;
}

test('installer copies differ only by the reviewed changes', () => {
  const pending = changeGroups(installerDiff(0)).map((group) => JSON.stringify([group.minus, group.plus]));
  const missing = approvedDifferences.filter((entry) => {
    const index = pending.indexOf(JSON.stringify([entry.minus, entry.plus]));
    if (index < 0) return true;
    pending.splice(index, 1);
    return false;
  });

  const failures = [];
  if (pending.length) {
    failures.push(
      `${repositoryCopy} and ${webCopy} differ in unreviewed ways; re-review the copies ` +
      `and update the approved differences (see docs/installer-copy-comparison.md):\n${installerDiff(3)}`,
    );
  }
  if (missing.length) {
    failures.push(
      `Reviewed differences are no longer present; refresh the approved differences and the review docs:\n` +
      missing.map((entry) => `- ${entry.name}`).join('\n'),
    );
  }
  if (failures.length) assert.fail(failures.join('\n\n'));
});

test('approved differences remain anchored in both installer copies', () => {
  const repository = readFileSync(new URL(`../${repositoryCopy}`, import.meta.url), 'utf8');
  const web = readFileSync(new URL(`../${webCopy}`, import.meta.url), 'utf8');
  for (const entry of approvedDifferences) {
    assert.ok(
      repository.includes(entry.minus.join('\n')),
      `"${entry.name}" is not present verbatim in ${repositoryCopy}; refresh the approved differences`,
    );
    assert.ok(
      web.includes(entry.plus.join('\n')),
      `"${entry.name}" is not present verbatim in ${webCopy}; refresh the approved differences`,
    );
  }
});
