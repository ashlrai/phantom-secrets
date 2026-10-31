// Run the colocated TSX tests through the same Node/TypeScript harness as the web tests.
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const ts = require("typescript");

const dom = new JSDOM("<!doctype html><html><body></body></html>", { url: "http://localhost/" });
global.window = dom.window;
global.document = dom.window.document;
Object.defineProperty(global, "navigator", { value: dom.window.navigator, configurable: true });
global.HTMLElement = dom.window.HTMLElement;
global.Node = dom.window.Node;

const React = require("react");
function load(file, dependencies = {}) {
  const source = fs.readFileSync(path.join(__dirname, "../src", file), "utf8");
  const output = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, target: ts.ScriptTarget.ES2022, esModuleInterop: true },
    fileName: file,
  }).outputText;
  const exports = {};
  new Function("exports", "require", output)(exports, (name) => dependencies[name] ?? require(name));
  return exports;
}

const release = load("lib/public-release.ts");
const icons = load("components/landing/Icons.tsx");
const copyButton = load("components/landing/CopyButton.tsx", {
  "./Icons": icons,
  "@/lib/posthog": { capturePostHog: async () => {} },
});
const quickStart = load("components/landing/QuickStart.tsx", {
  "./CopyButton": copyButton,
  "@/lib/public-release": release,
  "next/link": { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) },
});
load("components/landing/quickstart-accessibility.test.tsx", {
  "./QuickStart": quickStart,
  "@/lib/public-release": release,
});
// Keep the colocated rendering tests in the normal web test suite as well.
for (const file of ["QuickStart.test.tsx", "quickstart-tempdir.test.tsx"]) {
  load(`components/landing/${file}`, { "./QuickStart": quickStart });
}
