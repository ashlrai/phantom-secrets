// Run the colocated TS parity test through the same Node/TypeScript harness as the web tests.
const fs = require("node:fs");
const path = require("node:path");
const ts = require("typescript");
const React = require("react");

let selected = "macOS";
const hooks = {
  ...React,
  useState() {
    return [selected, (value) => { selected = value; }];
  },
};

function load(file, dependencies = {}) {
  const filename = path.join(__dirname, "..", file);
  const output = ts.transpileModule(fs.readFileSync(filename, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, target: ts.ScriptTarget.ES2022, esModuleInterop: true },
    fileName: file,
  }).outputText;
  const exports = {};
  new Function("exports", "require", "__dirname", "__filename", output)(
    exports,
    (name) => dependencies[name] ?? require(name),
    path.dirname(filename),
    filename,
  );
  return exports;
}

const release = load("src/lib/public-release.ts");
const { QuickStart } = load("src/components/landing/QuickStart.tsx", {
  react: hooks,
  "next/link": { __esModule: true, default: () => null },
  "@/lib/public-release": release,
  "./CopyButton": { CopyButton: () => null },
});
load("src/components/landing/quickstart-command-parity.test.ts", {
  "./QuickStart": { QuickStart },
  "@/lib/public-release": release,
});
