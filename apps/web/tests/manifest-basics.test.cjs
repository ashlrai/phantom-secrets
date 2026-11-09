const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const publicDir = path.resolve(__dirname, "../public");
const manifest = JSON.parse(
  fs.readFileSync(path.join(publicDir, "manifest.webmanifest"), "utf8"),
);

test("manifest declares at least one icon", () => {
  assert.ok(Array.isArray(manifest.icons));
  assert.ok(manifest.icons.length > 0);
});

test("every manifest icon has a nonempty src and an explicit sizes value", () => {
  manifest.icons.forEach((icon, index) => {
    const label = `icons[${index}]`;
    assert.equal(typeof icon.src, "string", `${label}.src must be a string`);
    assert.notEqual(icon.src.trim(), "", `${label}.src must not be empty`);
    assert.equal(typeof icon.sizes, "string", `${label}.sizes must be a string`);
    assert.notEqual(icon.sizes.trim(), "", `${label}.sizes must not be empty`);
    assert.match(
      icon.sizes.trim(),
      /^(any|\d+x\d+(\s+\d+x\d+)*)$/,
      `${label}.sizes must be "any" or space-separated WxH values`,
    );
  });
});

test("every local manifest icon src points at a file in public/", () => {
  for (const icon of manifest.icons) {
    if (/^[a-z][a-z0-9+.-]*:/i.test(icon.src)) continue;
    assert.ok(icon.src.startsWith("/"), `${icon.src} must be root-relative`);
    assert.ok(
      fs.existsSync(path.join(publicDir, icon.src.slice(1))),
      `${icon.src} must exist in public/`,
    );
  }
});
