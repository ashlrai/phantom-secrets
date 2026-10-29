const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { JSDOM } = require("jsdom");
const ts = require("typescript");

const dom = new JSDOM("<!doctype html><html><body></body></html>", { url: "http://localhost/" });
global.window = dom.window;
global.document = dom.window.document;
Object.defineProperty(global, "navigator", { value: dom.window.navigator, configurable: true });
global.HTMLElement = dom.window.HTMLElement;

const React = require("react");
const { cleanup, render, screen, waitFor } = require("@testing-library/react");
const userEvent = require("@testing-library/user-event").default;

function compile(file, localRequire) {
  const input = fs.readFileSync(path.join(__dirname, "../src", file), "utf8");
  const output = ts.transpileModule(input, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, target: ts.ScriptTarget.ES2022, esModuleInterop: true },
    fileName: file,
  }).outputText;
  const exports = {};
  new Function("exports", "require", output)(exports, localRequire);
  return exports;
}

const icons = compile("components/landing/Icons.tsx", require);
const release = compile("lib/public-release.ts", require);
const copyButton = compile("components/landing/CopyButton.tsx", (name) => {
  if (name === "./Icons") return icons;
  if (name === "@/lib/posthog") return { capturePostHog: async () => {} };
  return require(name);
});
const { QuickStart } = compile("components/landing/QuickStart.tsx", (name) => {
  if (name === "./CopyButton") return copyButton;
  if (name === "@/lib/public-release") return release;
  if (name === "next/link") return { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) };
  return require(name);
});

test("QuickStart copy controls are named, reachable by Tab, and operable by keyboard", async () => {
  const user = userEvent.setup();
  render(React.createElement(QuickStart));
  try {
    const buttons = screen.getAllByRole("button", { name: /^Copy command:/ });
    assert.equal(buttons.length, 3, "the selected platform and each setup step have a named copy button");
    assert.equal(screen.getByRole("button", { name: "Copy command: phantom init" }), buttons[2]);

    const reached = [];
    for (let i = 0; i < 40 && reached.length < buttons.length; i++) {
      await user.tab();
      if (buttons.includes(document.activeElement)) reached.push(document.activeElement);
    }
    assert.deepEqual(reached, buttons, "Tab reaches every copy button in document order");

    for (const key of ["{Enter}", " "]) {
      await navigator.clipboard.writeText("");
      await user.keyboard(key);
      await waitFor(async () => assert.equal(await navigator.clipboard.readText(), "phantom init"));
      assert.equal(document.activeElement, buttons[2], "copying keeps focus on the control");
    }
  } finally {
    cleanup();
  }
});
