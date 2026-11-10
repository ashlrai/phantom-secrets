// Run the colocated TypeScript test through the web suite's offline adapter.
const fs = require("node:fs");
const path = require("node:path");
const React = require("react");
const ts = require("typescript");

function compile(file, localRequire = require) {
  const source = fs.readFileSync(path.join(__dirname, "../src", file), "utf8");
  const output = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
    fileName: file,
  }).outputText;
  const exports = {};
  new Function("exports", "require", output)(exports, localRequire);
  return exports;
}

let selected = "macOS";
const release = compile("lib/public-release.ts");
const quickStart = compile("components/landing/QuickStart.tsx", (name) => {
  if (name === "react") return { ...React, useState: () => [selected, (value) => { selected = value; }] };
  if (name === "next/link") return { __esModule: true, default: () => null };
  if (name === "./CopyButton") return { CopyButton: () => null };
  if (name === "@/lib/public-release") return release;
  return require(name);
});
compile("components/landing/quick-start-stage-order.test.ts", (name) =>
  name === "./QuickStart" ? quickStart : require(name));
