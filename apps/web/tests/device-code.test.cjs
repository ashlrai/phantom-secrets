const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const source = fs.readFileSync(path.join(__dirname, "../src/lib/device-code.ts"), "utf8");
const output = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;
const deviceCodeModule = { exports: {} };
new Function("module", "exports", output)(deviceCodeModule, deviceCodeModule.exports);
const { formatDeviceUserCode, normalizeDeviceUserCode } = deviceCodeModule.exports;

test("complete device user codes display in two four-character groups and normalize for storage", () => {
  for (const canonical of ["ABCD2345", "WXYZ6789"]) {
    const displayed = formatDeviceUserCode(canonical);
    assert.match(displayed, /^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    assert.equal(displayed, `${canonical.slice(0, 4)}-${canonical.slice(4)}`);
    assert.equal(normalizeDeviceUserCode(displayed), canonical);
  }
});

test("internal device-code note matches the public form and formatter", () => {
  const notes = fs.readFileSync(path.join(__dirname, "../../../docs/internal/notes.md"), "utf8");
  const form = fs.readFileSync(path.join(__dirname, "../src/app/device/device-authorization-client.tsx"), "utf8");
  const note = notes.match(/### Device Auth Wave\n([\s\S]*?)(?=\n### )/);
  assert.ok(note, "device auth note exists");
  assert.match(note[1], /eight uppercase letters or numbers as `XXXX-XXXX`/);
  assert.match(note[1], /separator is not part of the code, so the display is nine characters long/);
  const placeholder = form.match(/placeholder="(XXXX-XXXX)"/);
  assert.ok(placeholder, "public form displays the documented pattern");
  assert.equal(formatDeviceUserCode("XXXXXXXX"), placeholder[1]);
  assert.equal(normalizeDeviceUserCode(placeholder[1]).length, 8);
  assert.equal(placeholder[1].length, 9);
});
