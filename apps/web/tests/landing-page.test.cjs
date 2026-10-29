// The web suite uses node:test with CommonJS; compile the TypeScript case into it.
const fs = require("node:fs");
const path = require("node:path");
const ts = require("typescript");

const file = path.join(__dirname, "landing-page.test.ts");
const output = ts.transpileModule(fs.readFileSync(file, "utf8"), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, esModuleInterop: true },
  fileName: file,
}).outputText;
new Function("exports", "require", "__dirname", output)({}, require, __dirname);
