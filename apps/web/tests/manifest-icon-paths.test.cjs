const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const publicDir = fs.realpathSync(path.join(__dirname, '../public'));
const manifest = JSON.parse(fs.readFileSync(path.join(publicDir, 'manifest.webmanifest'), 'utf8'));

test('local manifest icons resolve to files within public', () => {
  assert.ok(Array.isArray(manifest.icons) && manifest.icons.length > 0, 'manifest must declare icons');

  for (const icon of manifest.icons) {
    assert.equal(typeof icon.src, 'string', 'each icon must have a src');
    assert.ok(icon.src.trim(), 'icon src must not be empty');
    const url = new URL(icon.src, 'https://manifest.test/manifest.webmanifest');
    if (url.origin !== 'https://manifest.test') continue;

    const iconPath = path.join(publicDir, decodeURIComponent(url.pathname));
    const resolved = fs.realpathSync(iconPath);
    assert.ok(resolved.startsWith(publicDir + path.sep), `${icon.src} must stay within public`);
    assert.ok(fs.statSync(resolved).isFile(), `${icon.src} must resolve to a file`);
  }
});
