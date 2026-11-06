import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const read = (path) => readFileSync(resolve(root, path), 'utf8');

const OPEN_FENCE = /^ {0,3}(`{3,}|~{3,})/;
const CLOSE_FENCE = /^ {0,3}(`{3,}|~{3,})[ \t]*$/;

// Returns the 1-based line of an opening fence that never closes, or null
// when every fenced code block has a matching closer. A fence opens on three
// or more backticks or tildes indented at most three spaces and closes only
// on a bare run of the same marker at least as long as the opener; anything
// else on the closer's line leaves the block open.
function unclosedFence(markdown) {
  let open = null;
  const lines = markdown.replace(/\r\n?/g, '\n').split('\n');
  for (let index = 0; index < lines.length; index += 1) {
    const match = lines[index].match(open === null ? OPEN_FENCE : CLOSE_FENCE);
    if (open === null) {
      if (match) open = { char: match[1][0], length: match[1].length, line: index + 1 };
    } else if (match && match[1][0] === open.char && match[1].length >= open.length) {
      open = null;
    }
  }
  return open?.line ?? null;
}

test('internal notes: every fenced code block has a matching closing fence', () => {
  const line = unclosedFence(read('docs/internal/notes.md'));
  assert.equal(line, null, `docs/internal/notes.md: fence opened at line ${line} is never closed`);
});

test('every repository markdown file keeps fenced code blocks closed', () => {
  const ignored = new Set(['.git', '.next', 'coverage', 'dist', 'node_modules', 'out', 'target']);
  const files = readdirSync(root, { recursive: true })
    .filter((name) => name.endsWith('.md') && !name.split(sep).some((part) => ignored.has(part)));
  const failures = files.flatMap((name) => {
    const line = unclosedFence(readFileSync(resolve(root, name), 'utf8'));
    return line === null ? [] : `${name.split(sep).join('/')}: fence opened at line ${line} is never closed`;
  });
  assert.deepEqual(failures, []);
});

test('fence scanner flags every unmatched opener', () => {
  for (const balanced of [
    '```sh\nls\n```\n',
    '~~~text\na\n~~~\n',
    'text\n   ```js\nx\n   ```\n',
    '```\n```\n````\n````\n',
    '````\n```\n````\n',
    '```\ncode\n````\n',
    'no fences at all',
    '    ```\n    indented code, not a fence\n',
    '```sh\r\nls\r\n```\r\n',
  ]) {
    assert.equal(unclosedFence(balanced), null, JSON.stringify(balanced));
  }
  for (const [broken, line] of [
    ['```sh\nls\n', 1],
    ['intro\n```\ncode', 2],
    ['```\n~~~\n', 1],
    ['````\n```\n', 1],
    ['```\ncode\n``` extra\n', 1],
    ['```\ncode\n```\ntail\n~~~\n', 5],
  ]) {
    assert.equal(unclosedFence(broken), line, JSON.stringify(broken));
  }
});
