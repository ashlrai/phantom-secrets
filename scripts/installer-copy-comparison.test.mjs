import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const root = fileURLToPath(new URL('..', import.meta.url));
const files = ['scripts/install.sh', 'apps/web/public/install.sh'];
const document = readFileSync(new URL('../docs/installer-copy-comparison.md', import.meta.url), 'utf8');
const command = document.match(/```sh\n([\s\S]*?)\n```/)?.[1];

test('installer comparison snapshot and command describe the checked-in copies', () => {
  const contents = files.map((file) => readFileSync(new URL(`../${file}`, import.meta.url)));
  for (const [index, file] of files.entries()) {
    const hash = createHash('sha256').update(contents[index]).digest('hex');
    assert.ok(document.includes(`\`${file}\`: \`${hash}\``), `Refresh the review snapshot for ${file}`);
  }

  const matches = contents[0].equals(contents[1]);
  assert.match(document, matches ? /the files \*\*match\*\*/ : /the files \*\*differ\*\*/);
  assert.ok(command, 'The comparison command must be present');
  assert.equal(
    execFileSync('/bin/sh', ['-c', command], { cwd: root, encoding: 'utf8' }).trim(),
    `Installer copies ${matches ? 'match' : 'differ'}`,
  );
});

test('documented comparison distinguishes equality, differences, and errors', () => {
  assert.ok(command, 'The comparison command must be present');
  const directory = mkdtempSync(join(tmpdir(), 'phantom-installer-comparison-'));
  try {
    mkdirSync(join(directory, 'scripts'), { recursive: true });
    mkdirSync(join(directory, 'apps/web/public'), { recursive: true });
    const run = () => spawnSync('/bin/sh', ['-c', command], { cwd: directory, encoding: 'utf8' });
    const missing = run();
    assert.notEqual(missing.status, 0);
    assert.match(missing.stderr, /Comparison failed/);

    writeFileSync(join(directory, files[0]), 'same\n');
    writeFileSync(join(directory, files[1]), 'same\n');
    const equal = run();
    assert.equal(equal.status, 0);
    assert.equal(equal.stdout.trim(), 'Installer copies match');

    writeFileSync(join(directory, files[1]), 'different\n');
    const different = run();
    assert.equal(different.status, 0);
    assert.equal(different.stdout.trim(), 'Installer copies differ');
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
