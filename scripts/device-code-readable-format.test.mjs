import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');

test('readable device code reference reflects and cites the source notes', () => {
  const doc = read('../docs/device-code-readable-format.md');
  const notes = read('../docs/internal/notes.md');
  const index = read('../docs/README.md');

  assert.match(notes, /### Device Auth Wave\n[\s\S]*?eight uppercase letters or digits/);
  assert.match(notes, /`XXXX-XXXX`: two groups of four code characters separated by a hyphen/);
  assert.match(doc, /`XXXX-XXXX`/);
  assert.match(doc, /eight uppercase letters or digits\s+in two groups of four/);
  assert.match(doc, /separated by a hyphen for readability/);
  assert.match(doc, /eight code characters and nine displayed characters/);
  assert.match(doc, /\]\(internal\/notes\.md#device-auth-wave\)/);
  assert.match(index, /\]\(device-code-readable-format\.md\)/);

  const example = doc.match(/`([A-Z0-9]{4}-[A-Z0-9]{4})`/)?.[1];
  assert.ok(example, 'include a readable example');
  assert.equal(example.length, 9);
  assert.equal(example.replace('-', '').length, 8);
});
