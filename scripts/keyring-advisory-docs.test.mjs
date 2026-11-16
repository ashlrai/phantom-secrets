import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import test from 'node:test';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const read = (path) => readFileSync(resolve(root, path), 'utf8');

const RETIRED = [
  ['RUSTSEC-2026-0370', 'zvariant'],
  ['RUSTSEC-2026-0371', 'zbus_names'],
  ['RUSTSEC-2026-0372', 'zvariant_derive'],
];

test('contributor guidance records the retired keyring advisory exceptions', () => {
  const policy = read('deny.toml');
  const guidance = read('CONTRIBUTING.md').split('### Keyring advisory exceptions')[1]?.split('\n##')[0];
  assert.ok(guidance, 'missing keyring advisory guidance');
  for (const [id, crate] of RETIRED) {
    assert.ok(!policy.includes(`id = "${id}"`), `${id} is still ignored; update the guidance`);
    assert.ok(guidance.includes(id) && guidance.includes(`\`${crate}\``), `${id} is undocumented`);
  }
  assert.match(guidance, /https:\/\/github\.com\/ashlrai\/phantom-secrets\/issues\/242/);
  assert.match(guidance, /eliminated the dependencies rather than upgraded/);
  assert.match(guidance, /dbus-secret-service-keyring-store/);
  assert.match(guidance, /docs\/design\/keyring-4-migration-scoping\.md/);
  assert.ok(read('docs/design/keyring-4-migration-scoping.md'));
});

test('internal notes record the landed keyring migration and each retired ignore', () => {
  const policy = read('deny.toml');
  const note = read('docs/internal/notes.md').split('## Keyring migration tracking')[1]?.split('\n## ')[0];
  assert.ok(note, 'missing keyring migration tracking note');
  assert.match(note, /https:\/\/github\.com\/ashlrai\/phantom-secrets\/issues\/242/);
  assert.match(note, /migration landed/i);
  assert.match(note, /eliminating the affected dependencies/i);
  assert.match(note, /\.\.\/design\/keyring-4-migration-scoping\.md/);
  for (const [id, crate] of RETIRED) {
    assert.ok(!policy.includes(`id = "${id}"`), `${id} is still ignored; update the note`);
    assert.ok(note.includes(`\`${id}\` — \`${crate}\``), `${id} and ${crate} are undocumented`);
  }
});
