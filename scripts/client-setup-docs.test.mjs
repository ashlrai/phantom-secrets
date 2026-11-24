import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');

test('client guides describe the bundled runtime and effect gates', () => {
  for (const path of ['docs/windsurf.md', 'docs/gemini-cli.md']) {
    const example = read(path).match(/```json\n([\s\S]*?)\n```/);
    assert.ok(example, `${path} shows an MCP config example`);
    assert.deepEqual(JSON.parse(example[1]).mcpServers.phantom.args, ['mcp', 'serve']);
  }
  for (const path of ['docs/windsurf.md', 'docs/cursor.md', 'docs/gemini-cli.md']) {
    const guide = read(path);
    assert.match(guide, /PHANTOM_MCP_EFFECTS=trusted-terminal/);
    assert.match(guide, /confirm: true/);
    assert.match(guide, /one-use/);
  }
});

test('setup reference covers supported clients and safe previews', () => {
  const guide = read('docs/getting-started.md');
  assert.match(guide, /phantom setup --client gemini/);
  assert.match(guide, /phantom setup --status/);
  assert.match(read('README.md'), /--dry-run.*previews Cursor, Windsurf, Codex, or Gemini/);
  const gemini = read('docs/gemini-cli.md');
  assert.match(gemini, /phantom setup --client gemini --dry-run/);
  assert.match(gemini, /~\/\.gemini\/settings\.json/);
});
