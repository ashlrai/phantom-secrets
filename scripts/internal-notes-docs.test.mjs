import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import test from 'node:test';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const read = (path) => readFileSync(resolve(root, path), 'utf8');

// ATX headings only count outside fenced code blocks: a `#`-led line inside a
// ```/~~~ fence is code, not a heading.
function atxHeadings(markdown) {
  const headings = [];
  let fence = null;
  markdown.split('\n').forEach((line, index) => {
    const marker = line.match(/^ {0,3}(`{3,}|~{3,})/)?.[1];
    if (marker) {
      if (fence === null) fence = marker[0];
      else if (marker[0] === fence) fence = null;
      return;
    }
    if (fence !== null) return;
    const atx = line.match(/^ {0,3}(#{1,6})(?:[ \t]+(.*?))?[ \t]*$/);
    if (atx) {
      // An optional closing `#` run is markup, not heading text.
      const text = (atx[2] ?? '').replace(/[ \t]+#+$/, '');
      headings.push({ line: index + 1, level: atx[1].length, text });
    }
  });
  return headings;
}

test('docs/internal/notes.md is a nonempty document', () => {
  assert.ok(read('docs/internal/notes.md').trim().length > 0, 'notes.md is empty');
});

test('docs/internal/notes.md has only nonempty Markdown headings', () => {
  const headings = atxHeadings(read('docs/internal/notes.md'));
  assert.ok(headings.length > 0, 'notes.md has no Markdown headings');
  for (const { line, text } of headings) {
    assert.ok(/[^#\s]/.test(text), `line ${line} is an empty heading`);
  }
});

test('docs/internal/notes.md opens with an H1 title and never skips a level', () => {
  const headings = atxHeadings(read('docs/internal/notes.md'));
  assert.equal(headings[0]?.level, 1, 'the first heading must be the H1 title');
  let previous = headings[0].level;
  for (const { line, level } of headings.slice(1)) {
    assert.ok(level <= previous + 1, `line ${line} jumps from H${previous} to H${level}`);
    previous = level;
  }
});
