import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
const installer = read('scripts/install.sh');
const doc = read('docs/installer-path-update-steps.md');

// Same function boundary as installer-path-temp-failure.test.mjs: the
// PATH-update function ends where the installer's top-level checks begin.
function pathUpdateFunction(source, file) {
  const start = source.indexOf('add_to_user_path() {\n');
  const end = source.indexOf('\n}\n\ncommand -v curl', start);
  assert.ok(start >= 0 && end > start, `${file}: locate the installer PATH-update function`);
  return source.slice(start, end + '\n}'.length);
}

function assertOrdered(haystack, fragments, label) {
  let previous = -1;
  for (const fragment of fragments) {
    const index = haystack.indexOf(fragment);
    assert.ok(index >= 0, `${label}: missing step ${fragment}`);
    assert.ok(index > previous, `${label}: out of order: ${fragment}`);
    previous = index;
  }
}

test('the installer creates temporary files and updates PATH in the documented order', () => {
  // Temporary-file creation order in the executed sequence: install lock,
  // staging root, staging children, backup name, then the PATH update call
  // site whose add_to_user_path creates the PATH siblings.
  assertOrdered(installer, [
    '\nacquire_install_lock\n',
    'stage_root="$(mktemp -d "$install_parent/.${install_name}.install.XXXXXX")"',
    'mkdir -m 700 "$download_dir" "$candidate_dir"',
    'backup_path="$install_parent/.${install_name}.backup.${stage_root##*.}"',
    'add_to_user_path "$INSTALL_DIR"',
  ], 'install.sh temporary-file creation');

  // PATH update order inside add_to_user_path: before file, candidate file,
  // marker short-circuit, PATH-line append, pre-move compare, move, snapshot
  // removal, post-move marker check.
  assertOrdered(pathUpdateFunction(installer, 'scripts/install.sh'), [
    'before_tmp="$(mktemp "$rc_parent/.phantom-path.before.XXXXXX")"',
    'candidate_tmp="$(mktemp "$rc_parent/.phantom-path.candidate.XXXXXX")"',
    'grep -qF "$marker" "$before_tmp"',
    '>> "$candidate_tmp"',
    'cmp -s "$before_tmp" "$rc"',
    'mv -f "$candidate_tmp" "$rc"',
    '\n  rm -f -- "$before_tmp"\n',
    'grep -qF "$marker" "$rc"',
  ], 'install.sh PATH update');

  // The call site checks exact PATH membership before invoking the update.
  const check = installer.indexOf('grep -qxF "$INSTALL_DIR"');
  const call = installer.indexOf('add_to_user_path "$INSTALL_DIR" || warn');
  assert.ok(check >= 0 && call > check,
    'the exact PATH entry check must gate add_to_user_path');
});

test('the document describes the PATH update steps in the same order', () => {
  const steps = doc.slice(doc.indexOf('## PATH update steps in order'));
  assert.ok(steps, 'document must have a PATH update steps section');
  assertOrdered(steps, [
    'grep -qxF',                       // exact PATH entry check
    'basename "${SHELL:-bash}"',       // startup file selection
    'pwd -P',                          // physical parent resolution
    '.phantom-path.before.XXXXXX',     // first temporary file
    '.phantom-path.candidate.XXXXXX',  // second temporary file
    'cp -p',                           // snapshot copy
    '# phantom-secrets PATH',          // marker short-circuit
    'cmp -s',                          // pre-move re-verification
    'mv -f',                           // replacement
    'not restored',                    // post-move failure limit
  ], 'installer-path-update-steps.md PATH update steps');
});

test('the document describes the temporary-file creation order', () => {
  const section = doc.slice(
    doc.indexOf('## Temporary-file creation order'),
    doc.indexOf('## PATH update steps in order'),
  );
  assert.ok(section, 'document must have a temporary-file creation order section');
  assertOrdered(section, [
    '.install.lock',
    '.install.XXXXXX',
    'download/',
    '.backup.',
    '.phantom-path.before.XXXXXX',
    '.phantom-path.candidate.XXXXXX',
  ], 'installer-path-update-steps.md temporary-file order');
});

test('the document covers the observable steps and artifacts', () => {
  for (const fragment of [
    '](../scripts/install.sh)',
    'apps/web/public/install.sh',
    'install.ps1',
    'umask 077', 'mktemp', 'mkdir -p', 'chmod 600',
    '.zshrc', 'config.fish', '.bashrc',
    'set -gx PATH', 'export PATH',
    'grep -qxF', 'cmp -s', 'mv -f', 'cp -p',
    'return 1', 'warn',
    'installer-path-update-flow.md', 'installer-path-update-reference.md',
  ]) assert.ok(doc.includes(fragment), `document must cover ${fragment}`);
});

test('the public installer copy still carries the identical PATH-update function', () => {
  assert.equal(
    pathUpdateFunction(installer, 'scripts/install.sh'),
    pathUpdateFunction(read('apps/web/public/install.sh'), 'apps/web/public/install.sh'),
    'the document claims both Unix installer copies share this function',
  );
});

test('ordering assertions reject a reordered or missing step', () => {
  const body = pathUpdateFunction(installer, 'scripts/install.sh');
  assert.throws(
    () => assertOrdered(body.replace('mv -f "$candidate_tmp" "$rc"', ''),
      ['cmp -s "$before_tmp" "$rc"', 'mv -f "$candidate_tmp" "$rc"'], 'fixture'),
    /missing step/,
  );
  const swapped = body
    .replace('.phantom-path.before.XXXXXX', '.phantom-path.zzswap.XXXXXX')
    .replace('.phantom-path.candidate.XXXXXX', '.phantom-path.before.XXXXXX')
    .replace('.phantom-path.zzswap.XXXXXX', '.phantom-path.candidate.XXXXXX');
  assert.throws(
    () => assertOrdered(swapped,
      ['.phantom-path.before.XXXXXX', '.phantom-path.candidate.XXXXXX'], 'fixture'),
    /out of order/,
  );
});
