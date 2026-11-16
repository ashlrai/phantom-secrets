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
global.Node = dom.window.Node;
global.HTMLElement = dom.window.HTMLElement;
Object.defineProperty(global, "navigator", { value: dom.window.navigator, configurable: true });
const { cleanup, fireEvent, render, screen, waitFor } = require("@testing-library/react");

function load(file, dependencies = {}) {
  const source = fs.readFileSync(path.join(__dirname, "../src", file), "utf8");
  const output = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
  }).outputText;
  const exports = {};
  new Function("exports", "require", output)(exports, (name) => dependencies[name] ?? require(name));
  return exports;
}

const events = [];
const copy = load("components/landing/CopyButton.tsx", {
  "./Icons": load("components/landing/Icons.tsx"),
  "@/lib/posthog": { capturePostHog: (event) => { events.push(event); } },
});
const { QuickStart } = load("components/landing/QuickStart.tsx", {
  "./CopyButton": copy,
  "@/lib/public-release": load("lib/public-release.ts"),
  "next/link": { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) },
});

test("a rejected QuickStart clipboard write reports failure and allows a retry", async () => {
  const original = Object.getOwnPropertyDescriptor(navigator, "clipboard");
  let rejectWrite;
  const writes = [];
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText: (text) => {
      writes.push(text);
      return writes.length === 1 ? new Promise((_, reject) => { rejectWrite = reject; }) : Promise.resolve();
    } },
  });
  try {
    render(React.createElement(QuickStart));
    const button = screen.getByRole("button", { name: "Copy command: phantom init" });
    const feedback = button.querySelector('[aria-live="polite"]');
    fireEvent.click(button);
    assert.deepEqual(writes, ["phantom init"]);
    assert.equal(feedback.textContent, "");
    rejectWrite(new Error("clipboard denied"));
    await waitFor(() => assert.equal(feedback.textContent, "Copy failed; select the command manually"));
    assert.equal(button.title, "Copy failed; select the command manually");
    assert.equal(screen.queryByText("Copied"), null);
    assert.deepEqual(events, []);
    fireEvent.click(button);
    await waitFor(() => assert.equal(feedback.textContent, "Copied"));
    assert.deepEqual(writes, ["phantom init", "phantom init"]);
    assert.deepEqual(events, ["command_copied"]);
  } finally {
    cleanup();
    if (original) Object.defineProperty(navigator, "clipboard", original);
    else delete navigator.clipboard;
    dom.window.close();
  }
});
