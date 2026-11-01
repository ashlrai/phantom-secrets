// Node's test runner cannot execute TSX directly. Compile the adjacent test
// with the same TypeScript dependency used by the application.
import fs from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { compileFunction } from "node:vm";
import ts from "typescript";

const filename = fileURLToPath(new URL("./device-code-placeholder.test.tsx", import.meta.url));
const output = ts.transpileModule(fs.readFileSync(filename, "utf8"), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
  fileName: filename,
}).outputText;
const testModule = { exports: {} };
compileFunction(output, ["require", "module", "exports", "__filename"], { filename })(
  createRequire(filename), testModule, testModule.exports, filename,
);
