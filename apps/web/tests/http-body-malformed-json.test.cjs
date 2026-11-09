const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const file = path.join(__dirname, "../src/lib/http-body.ts");
const output = ts.transpileModule(fs.readFileSync(file, "utf8"), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  fileName: file,
}).outputText;
const helper = { exports: {} };
new Function("exports", "require", "module", output)(helper.exports, require, helper);
const { readBoundedJsonObject, RequestBodyError, requestBodyErrorResponse } = helper.exports;

test("malformed JSON rejects without returning a partially parsed object", async () => {
  for (const payload of ['{"accepted":true,', '{"accepted":true} trailing']) {
    const request = new Request("https://phm.dev/test", { method: "POST", body: payload });
    let failure;
    await assert.rejects(readBoundedJsonObject(request, 1024), (error) => {
      assert.ok(error instanceof RequestBodyError);
      assert.equal(error.code, "invalid_body");
      assert.equal(error.status, 400);
      failure = error;
      return true;
    });
    const response = requestBodyErrorResponse(failure);
    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), { error: "invalid_body" });
  }
});
