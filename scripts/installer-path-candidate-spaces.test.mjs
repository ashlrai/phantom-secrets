import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import test from 'node:test';

// First-time installs have no shell startup file yet. The PATH update must
// still create its candidate (.phantom-path.candidate.XXXXXX) directly inside
// the intended parent — here a space-containing HOME — and move it into place
// as the new startup file, leaving nothing behind.
const copies = {
  'scripts/install.sh': resolve(import.meta.dirname, 'install.sh'),
  'apps/web/public/install.sh': resolve(import.meta.dirname, '..', 'apps', 'web', 'public', 'install.sh'),
};

function extractFunction(source, name, file) {
  const start = source.indexOf(`${name}()`);
  assert.ok(start >= 0, `${file}: locate ${name}`);
  const lineEnd = source.indexOf('\n', start);
  if (source.slice(start, lineEnd).trimEnd().endsWith('}')) {
    return source.slice(start, lineEnd + 1);
  }
  const end = source.indexOf('\n}\n', start);
  assert.ok(end > start, `${file}: locate end of ${name}`);
  return source.slice(start, end + '\n}\n'.length);
}

function harness(source, file) {
  return ['set -euo pipefail', 'umask 077',
    ...['say', 'file_identity', 'file_link_count', 'add_to_user_path']
      .map((name) => extractFunction(source, name, file)),
    'add_to_user_path "$1"',
  ].join('\n');
}

// Records the real path mktemp creates, then delegates to the real tool.
function makeMktempShim(root) {
  const shims = join(root, 'shims');
  mkdirSync(shims);
  const mktemp = execFileSync('which', ['mktemp'], { encoding: 'utf8' }).trim();
  writeFileSync(join(shims, 'mktemp'), `#!/bin/sh
created="$(${JSON.stringify(mktemp)} "$@")" || exit
printf '%s\\n' "$created" >> "$PHANTOM_TEST_MKTEMP_CREATED"
printf '%s\\n' "$created"
`);
  chmodSync(join(shims, 'mktemp'), 0o755);
  return shims;
}

for (const [file, installer] of Object.entries(copies)) {
  const script = harness(readFileSync(installer, 'utf8'), file);
  test(`${file} creates the PATH candidate under a space-containing parent when no startup file exists`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-candidate-spaces-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const home = join(root, 'home dir with spaces');
    const bin = join(root, 'bin');
    const scratch = join(root, 'scratch');
    mkdirSync(home);
    mkdirSync(bin);
    mkdirSync(scratch);
    const rc = join(home, '.bashrc');
    const created = join(root, 'mktemp-created');
    const result = spawnSync('/bin/bash', ['-c', script, 'path-test', bin], {
      encoding: 'utf8',
      timeout: 30000,
      cwd: scratch,
      env: {
        HOME: home,
        SHELL: '/bin/bash',
        PATH: `${makeMktempShim(root)}:/usr/bin:/bin`,
        PHANTOM_TEST_MKTEMP_CREATED: created,
      },
    });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);

    assert.ok(existsSync(created), 'mktemp ran');
    const candidates = readFileSync(created, 'utf8').trim().split('\n')
      .filter((path) => basename(path).startsWith('.phantom-path.candidate.'));
    assert.equal(candidates.length, 1, 'exactly one candidate was created');
    assert.equal(dirname(candidates[0]), home,
      'the candidate must be created directly inside the spaced parent');

    // The candidate became the startup file; no temporary siblings or path
    // fragments remain anywhere.
    assert.equal(existsSync(candidates[0]), false, 'candidate was moved into place');
    assert.deepEqual(readdirSync(home), ['.bashrc']);
    assert.deepEqual(readdirSync(scratch), []);
    assert.equal(readFileSync(rc, 'utf8'),
      `\n# phantom-secrets PATH\nexport PATH="${bin}:$PATH"\n`);
  });
}
