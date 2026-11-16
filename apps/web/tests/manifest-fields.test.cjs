const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const manifestPath = path.resolve(__dirname, "../public/manifest.webmanifest");
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));

test("web manifest has a nonempty name", () => {
  assert.equal(typeof manifest.name, "string");
  assert.notEqual(manifest.name.trim(), "");
});

test("web manifest has a nonempty start_url inside its scope", () => {
  assert.equal(typeof manifest.start_url, "string");
  assert.notEqual(manifest.start_url.trim(), "");
  const base = "https://example.test";
  const start = new URL(manifest.start_url, base);
  const scope = new URL(manifest.scope ?? ".", new URL(manifest.start_url, base));
  assert.equal(start.origin, base);
  assert.ok(start.pathname.startsWith(scope.pathname));
});

test("web manifest icons each have a src and type", () => {
  assert.ok(Array.isArray(manifest.icons) && manifest.icons.length > 0);
  for (const icon of manifest.icons) {
    assert.ok(icon.src && icon.type);
    assert.ok(fs.existsSync(path.join(path.dirname(manifestPath), icon.src)));
  }
});
