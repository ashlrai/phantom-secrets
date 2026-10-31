// Run the colocated TSX test with the same TypeScript adapter used by web tests.
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const ts = require("typescript");
const React = require("react");

const dom = new JSDOM("<!doctype html><html><body></body></html>", { url: "http://localhost/" });
global.window = dom.window;
global.document = dom.window.document;
global.Node = dom.window.Node;
global.HTMLElement = dom.window.HTMLElement;
Object.defineProperty(global, "navigator", { value: dom.window.navigator, configurable: true });

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

const icons = compile("components/landing/Icons.tsx");
const release = compile("lib/public-release.ts");
const copyButton = compile("components/landing/CopyButton.tsx", (name) => {
  if (name === "./Icons") return icons;
  if (name === "@/lib/posthog") return { capturePostHog: async () => {} };
  return require(name);
});
const quickStart = compile("components/landing/QuickStart.tsx", (name) => {
  if (name === "./CopyButton") return copyButton;
  if (name === "@/lib/public-release") return release;
  if (name === "next/link") return { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) };
  return require(name);
});
compile("components/landing/QuickStart.test.tsx", (name) => name === "./QuickStart" ? quickStart : require(name));
compile("components/landing/quickstart-tempdir.test.tsx", (name) => name === "./QuickStart" ? quickStart : require(name));
