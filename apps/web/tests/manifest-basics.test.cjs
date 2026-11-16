const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const manifestPath = path.resolve(__dirname, "../public/manifest.webmanifest");
const readManifest = () => JSON.parse(fs.readFileSync(manifestPath, "utf8"));

test("web manifest parses as JSON", () => {
  assert.equal(typeof readManifest(), "object");
});

test("web manifest has nonempty name and short_name", () => {
  const manifest = readManifest();
  for (const field of ["name", "short_name"]) {
    assert.equal(typeof manifest[field], "string", `${field} must be a string`);
    assert.notEqual(manifest[field].trim(), "", `${field} must not be empty`);
  }
});
