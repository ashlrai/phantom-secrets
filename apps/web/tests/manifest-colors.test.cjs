const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const manifest = JSON.parse(fs.readFileSync(
  path.join(__dirname, "../public/manifest.webmanifest"), "utf8",
));

for (const field of ["theme_color", "background_color"]) {
  test(`manifest ${field} is a nonempty CSS hex color`, () => {
    assert.equal(typeof manifest[field], "string", `${field} must be a string`);
    assert.match(manifest[field], /^#(?:[\da-f]{3}|[\da-f]{4}|[\da-f]{6}|[\da-f]{8})$/i);
  });
}
