const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const file = path.join(__dirname, "../src/lib/http-body.ts");
const compiled = ts.transpileModule(fs.readFileSync(file, "utf8"), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  fileName: file,
}).outputText;
const helper = { exports: {} };
new Function("exports", "require", "module", compiled)(helper.exports, require, helper);

for (const payload of ['{"key":', '{"key": "value",}', 'not json']) {
  test(`malformed JSON is reported as invalid_body: ${payload}`, async () => {
    const request = new Request("https://phm.dev/test", { method: "POST", body: payload });
    let caught;
    await assert.rejects(helper.exports.readBoundedJsonObject(request, 100), (error) => {
      assert.ok(error instanceof helper.exports.RequestBodyError);
      assert.equal(error.code, "invalid_body");
      assert.equal(error.status, 400);
      caught = error;
      return true;
    });
    const response = helper.exports.requestBodyErrorResponse(caught);
    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), { error: "invalid_body" });
  });
}
