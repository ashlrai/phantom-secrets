const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const publicDir = path.resolve(__dirname, "..", "public");
const manifest = JSON.parse(
  fs.readFileSync(path.join(publicDir, "manifest.webmanifest"), "utf8"),
);

test("manifest declares at least one icon", () => {
  assert.ok(Array.isArray(manifest.icons));
  assert.ok(manifest.icons.length > 0);
});

test("every manifest icon has a source, size and type", () => {
  for (const icon of manifest.icons) {
    for (const field of ["src", "sizes", "type"]) {
      assert.equal(typeof icon[field], "string", `icon ${field} must be a string`);
      assert.ok(icon[field].trim().length > 0, `icon ${field} must be nonempty`);
    }
  }
});

test("every local manifest icon points to an existing file", () => {
  for (const icon of manifest.icons) {
    if (/^[a-z][a-z0-9+.-]*:|^\/\//i.test(icon.src)) continue; // remote asset
    assert.ok(icon.src.startsWith("/"), `${icon.src} must be root-relative`);
    const file = path.join(publicDir, decodeURIComponent(icon.src.split(/[?#]/)[0]));
    assert.ok(file.startsWith(publicDir + path.sep), `${icon.src} escapes public/`);
    assert.ok(fs.statSync(file).isFile(), `${icon.src} missing at ${file}`);
    assert.ok(fs.statSync(file).size > 0, `${icon.src} is empty`);
  }
});
