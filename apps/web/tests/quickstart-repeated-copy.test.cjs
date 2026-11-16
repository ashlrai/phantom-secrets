const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { JSDOM } = require("jsdom");
const ts = require("typescript");
const React = require("react");

const dom = new JSDOM("<!doctype html><html><body></body></html>", { url: "http://localhost/" });
global.window = dom.window;
global.document = dom.window.document;
global.HTMLElement = dom.window.HTMLElement;
global.Node = dom.window.Node;
Object.defineProperty(global, "navigator", { value: dom.window.navigator, configurable: true });
const { cleanup, fireEvent, render, screen, within, waitFor } = require("@testing-library/react");

function load(file, dependencies = {}) {
  const source = fs.readFileSync(path.join(__dirname, "../src", file), "utf8");
  const output = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
  }).outputText;
  const exports = {};
  new Function("exports", "require", output)(exports, (name) => dependencies[name] ?? require(name));
  return exports;
}

const copy = load("components/landing/CopyButton.tsx", {
  "./Icons": load("components/landing/Icons.tsx"),
  "@/lib/posthog": { capturePostHog: async () => {} },
});
const { QuickStart } = load("components/landing/QuickStart.tsx", {
  "./CopyButton": copy,
  "@/lib/public-release": load("lib/public-release.ts"),
  "next/link": { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) },
});

test("repeated install copies always use the currently displayed command", async () => {
  const originalClipboard = Object.getOwnPropertyDescriptor(navigator, "clipboard");
  const writes = [];
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText: async (text) => { writes.push(text); } },
  });
  try {
    render(React.createElement(QuickStart));
    const selector = screen.getByRole("group", { name: "Choose an operating system" });
    let expectedWrites = 0;
    for (const platform of ["macOS", "Windows", "Linux", "macOS"]) {
      fireEvent.click(within(selector).getByRole("button", { name: platform }));
      const card = screen.getByRole("heading", { level: 3, name: platform }).closest("article");
      const button = within(card).getByRole("button", { name: /^Copy command: / });
      const displayed = button.firstElementChild.lastChild.textContent;
      assert.ok(displayed, `${platform}: command is displayed`);
      for (let i = 0; i < 2; i++) {
        fireEvent.click(button);
        expectedWrites++;
        assert.equal(writes.length, expectedWrites, `${platform}: every activation writes once`);
        assert.equal(writes.at(-1), displayed, `${platform}: copied command matches display`);
        await waitFor(() => assert.equal(within(button).getByText("Copied").textContent, "Copied"));
      }
    }
  } finally {
    cleanup();
    if (originalClipboard) Object.defineProperty(navigator, "clipboard", originalClipboard);
    else delete navigator.clipboard;
    dom.window.close();
  }
});
