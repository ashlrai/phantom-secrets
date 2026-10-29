// Load the TypeScript case through the same compiler used by the other web tests.
const fs = require("node:fs");
const Module = require("node:module");
const ts = require("typescript");
const filename = require("node:path").join(__dirname, "landing-page.test.ts");
const compiled = ts.transpileModule(fs.readFileSync(filename, "utf8"), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, esModuleInterop: true },
  fileName: filename,
}).outputText;
const testModule = new Module(filename, module);
testModule.filename = filename;
testModule.paths = module.paths;
testModule._compile(compiled, filename);
