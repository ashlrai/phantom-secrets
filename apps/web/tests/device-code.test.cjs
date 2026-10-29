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
const { formatDeviceUserCode, isValidDeviceUserCode, normalizeDeviceUserCode } = deviceCodeModule.exports;

test("complete device user codes display in two four-character groups and normalize for storage", () => {
  for (const canonical of ["ABCD2345", "WXYZ6789"]) {
    const displayed = formatDeviceUserCode(canonical);
    assert.match(displayed, /^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    assert.equal(displayed, `${canonical.slice(0, 4)}-${canonical.slice(4)}`);
    assert.equal(normalizeDeviceUserCode(displayed), canonical);
  }
});

test("input normalization accepts lowercase and separators while requiring eight characters", () => {
  for (const input of ["abcd2345", "abcd-2345", "ab cd-23 45!"]) {
    assert.equal(normalizeDeviceUserCode(input), "ABCD2345");
    assert.equal(formatDeviceUserCode(input), "ABCD-2345");
    assert.equal(isValidDeviceUserCode(input), true);
  }
  for (const [input, displayed] of [["ab-cd", "ABCD"], ["abc-d2", "ABCD-2"]]) {
    assert.equal(formatDeviceUserCode(input), displayed);
    assert.equal(isValidDeviceUserCode(input), false);
  }
});

test("formatting preserves extra characters so overlong codes remain invalid", () => {
  const displayed = formatDeviceUserCode("abcd-23456");
  assert.equal(displayed, "ABCD-23456");
  assert.equal(normalizeDeviceUserCode(displayed), "ABCD23456");
  assert.equal(isValidDeviceUserCode(displayed), false);
});
