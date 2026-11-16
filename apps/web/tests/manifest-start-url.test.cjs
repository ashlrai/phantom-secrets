const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const manifest = JSON.parse(
  fs.readFileSync(
    path.resolve(__dirname, "..", "public", "manifest.webmanifest"),
    "utf8",
  ),
);

test("manifest start_url is a local absolute path", () => {
  const { start_url: startUrl } = manifest;
  assert.equal(typeof startUrl, "string");
  assert.match(startUrl, /^\/(?!\/)/, "must start with a single '/'");
  assert.doesNotMatch(startUrl, /^[a-z][a-z0-9+.-]*:/i, "must have no scheme");
  assert.doesNotMatch(startUrl, /\\/, "must not contain backslashes");
});

test("manifest start_url has no fragment", () => {
  assert.ok(!manifest.start_url.includes("#"));
});

test("manifest start_url stays inside scope", () => {
  const origin = "https://example.test";
  const start = new URL(manifest.start_url, origin);
  const scope = new URL(manifest.scope, origin);
  assert.equal(start.origin, origin);
  assert.ok(start.pathname.startsWith(scope.pathname));
});
