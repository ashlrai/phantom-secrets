const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const source = fs.readFileSync(path.join(__dirname, "../src/lib/http-body.ts"), "utf8");
const output = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;
const body = { exports: {} };
new Function("exports", "require", "module", output)(body.exports, require, body);

for (const [label, requestBody] of [["absent", undefined], ["empty", ""]]) {
  test(`${label} body returns empty text and rejects JSON`, async () => {
    const request = () => new Request("https://phm.dev/test", {
      method: "POST",
      headers: { "content-length": "0" },
      body: requestBody,
    });
    assert.equal(await body.exports.readBoundedText(request(), 1), "");
    await assert.rejects(body.exports.readBoundedJsonObject(request(), 1), (error) => {
      assert.ok(error instanceof body.exports.RequestBodyError);
      assert.equal(error.code, "invalid_body");
      assert.equal(error.status, 400);
      return true;
    });
  });
}
