import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import test from 'node:test';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const read = (path) => readFileSync(resolve(root, path), 'utf8');

test('contributor guidance tracks the keyring advisory exceptions', () => {
  const policy = read('deny.toml');
  const guidance = read('CONTRIBUTING.md').split('### Keyring advisory exceptions')[1]?.split('\n##')[0];
  assert.ok(guidance, 'missing keyring advisory guidance');
  const ids = [...policy.matchAll(/id = "(RUSTSEC-[\d-]+)"[^\n]*keyring 3/g)].map((match) => match[1]);
  assert.ok(ids.length, 'update the guidance when the keyring exceptions are removed');
  for (const id of ids) assert.ok(guidance.includes(id), `${id} is undocumented`);
  assert.match(guidance, /https:\/\/github\.com\/ashlrai\/phantom-secrets\/issues\/242/);
  assert.match(guidance, /Removal depends on[\s\S]*?eliminating these dependencies/);
  assert.match(guidance, /docs\/design\/keyring-4-migration-scoping\.md/);
  assert.ok(read('docs/design/keyring-4-migration-scoping.md'));
});

test('internal notes track the outstanding keyring migration and each ignore', () => {
  const policy = read('deny.toml');
  const note = read('docs/internal/notes.md').split('## Keyring migration tracking')[1]?.split('\n## ')[0];
  assert.ok(note, 'missing keyring migration tracking note');
  assert.match(note, /https:\/\/github\.com\/ashlrai\/phantom-secrets\/issues\/242/);
  assert.match(note, /migration remains outstanding/i);
  assert.match(note, /eliminating the affected dependencies/i);
  assert.match(note, /\.\.\/design\/keyring-4-migration-scoping\.md/);
  for (const [id, crate] of [
    ['RUSTSEC-2026-0370', 'zvariant'],
    ['RUSTSEC-2026-0371', 'zbus_names'],
    ['RUSTSEC-2026-0372', 'zvariant_derive'],
  ]) {
    assert.ok(policy.includes(`id = "${id}"`), `${id} is no longer ignored; update the note`);
    assert.ok(note.includes(`\`${id}\` — \`${crate}\``), `${id} and ${crate} are undocumented`);
  }
});
