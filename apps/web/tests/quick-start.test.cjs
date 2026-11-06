// Run the colocated TSX staging-variable quoting test through the same
// Node/TypeScript harness as the web tests.
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

const webRoot = path.join(__dirname, "..");

function load(file, dependencies = {}) {
  const source = fs.readFileSync(path.join(webRoot, file), "utf8");
  const output = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, target: ts.ScriptTarget.ES2022, esModuleInterop: true },
    fileName: file,
  }).outputText;
  const exports = {};
  new Function("exports", "require", output)(exports, (name) => dependencies[name] ?? require(name));
  return exports;
}

const release = load("src/lib/public-release.ts");
const icons = load("src/components/landing/Icons.tsx");
const copyButton = load("src/components/landing/CopyButton.tsx", {
  "./Icons": icons,
  "@/lib/posthog": { capturePostHog: async () => {} },
});
const quickStart = load("src/components/landing/QuickStart.tsx", {
  "./CopyButton": copyButton,
  "@/lib/public-release": release,
  "next/link": { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) },
});
load("tests/quick-start.test.tsx", {
  "../src/components/landing/QuickStart": quickStart,
});
