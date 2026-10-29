// Load the TypeScript test through the same compiler used by the other web tests.
const fs = require("node:fs");
const Module = require("node:module");
const path = require("node:path");
const ts = require("typescript");

const filename = path.join(__dirname, "landing-page.test.ts");
const source = fs.readFileSync(filename, "utf8");
const output = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, esModuleInterop: true },
  fileName: filename,
}).outputText;
const loaded = new Module(filename, module);
loaded.filename = filename;
loaded.paths = module.paths;
loaded._compile(output, filename);
