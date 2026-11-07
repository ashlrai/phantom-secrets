import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');

test('device code readability doc matches notes and cites them', () => {
  const doc = read('../docs/device-code-readability.md');
  const notes = read('../docs/internal/notes.md');
  const index = read('../docs/README.md');

  assert.match(notes, /### Device Auth Wave\n/);
  assert.match(notes, /`XXXX-XXXX`: two groups of four code characters separated by a hyphen/);
  assert.match(doc, /eight uppercase letters or digits/);
  assert.match(doc, /`XXXX-XXXX`: two groups of four code characters\nseparated by a hyphen/);
  assert.match(doc, /eight code characters and nine displayed characters/);
  assert.match(doc, /extra characters are not\s+silently truncated/);
  assert.match(doc, /\]\(internal\/notes\.md#device-auth-wave\)/);
  assert.match(index, /\]\(device-code-readability\.md\)/);
});

test('documented format agrees with the shared helper', () => {
  const src = read('../apps/web/src/lib/device-code.ts');
  assert.match(src, /DEVICE_USER_CODE_LENGTH = 8/);
  assert.match(src, /slice\(0, 4\)\}-\$\{normalized\.slice\(4\)/);
});
