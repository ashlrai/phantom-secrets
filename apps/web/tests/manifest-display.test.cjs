const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

// Display modes defined by the W3C Web App Manifest spec.
const DISPLAY_MODES = ["fullscreen", "standalone", "minimal-ui", "browser"];

const manifest = JSON.parse(
  fs.readFileSync(
    path.resolve(__dirname, "..", "public", "manifest.webmanifest"),
    "utf8",
  ),
);

test("manifest display is a recognized web app manifest display mode", () => {
  assert.equal(typeof manifest.display, "string");
  assert.ok(
    DISPLAY_MODES.includes(manifest.display),
    `display "${manifest.display}" must be one of: ${DISPLAY_MODES.join(", ")}`,
  );
});
