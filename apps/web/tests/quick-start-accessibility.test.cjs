// Run the colocated TSX tests through the same Node/TypeScript harness as the web tests.
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const ts = require("typescript");
const assert = require("node:assert/strict");
const test = require("node:test");

const dom = new JSDOM("<!doctype html><html><body></body></html>", { url: "http://localhost/" });
global.window = dom.window;
global.document = dom.window.document;
Object.defineProperty(global, "navigator", { value: dom.window.navigator, configurable: true });
global.HTMLElement = dom.window.HTMLElement;
global.Node = dom.window.Node;

const React = require("react");
const { cleanup, fireEvent, render, screen, waitFor, within } = require("@testing-library/react");
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

test("a successful QuickStart copy displays feedback for the selected command", async () => {
  const originalClipboard = Object.getOwnPropertyDescriptor(navigator, "clipboard");
  const copied = [];
  let finishCopy;
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText: (text) => { copied.push(text); return new Promise((resolve) => { finishCopy = resolve; }); } },
  });
  const style = document.createElement("style");
  style.textContent = fs.readFileSync(path.join(__dirname, "../src/app/globals.css"), "utf8");
  document.head.append(style);
  try {
    render(React.createElement(quickStart.QuickStart));
    const button = screen.getByRole("button", { name: "Copy command: phantom init" });
    const feedback = button.querySelector('[aria-live="polite"]');
    assert.ok(feedback);
    assert.equal(feedback.textContent, "");
    fireEvent.click(button);
    assert.deepEqual(copied, ["phantom init"]);
    assert.equal(feedback.textContent, "", "feedback waits for the clipboard operation to succeed");
    finishCopy();
    await waitFor(() => assert.equal(feedback.textContent, "Copied"));
    assert.equal(feedback.classList.contains("sr-only"), false);
    assert.equal(window.getComputedStyle(feedback).visibility, "visible");
    assert.notEqual(window.getComputedStyle(feedback).display, "none");
    assert.equal(within(button).getByText("Copied"), feedback);
    assert.equal(screen.getAllByText("Copied").length, 1);
  } finally {
    cleanup();
    style.remove();
    if (originalClipboard) Object.defineProperty(navigator, "clipboard", originalClipboard);
    else delete navigator.clipboard;
  }
});
test("accessibility review is discoverable and covers the review workflow", () => {
  const docs = path.join(__dirname, "../../../docs");
  const review = fs.readFileSync(path.join(docs, "quickstart-accessibility-review.md"), "utf8");
  assert.match(fs.readFileSync(path.join(docs, "README.md"), "utf8"), /\]\(quickstart-accessibility-review\.md\)/);
  for (const heading of ["Controls inventory", "Headings and structure", "Platform selection", "Command readability", "Keyboard access"]) {
    assert.ok(review.includes(`## ${heading}`), `missing checklist section: ${heading}`);
  }
  for (const item of [
    "macOS",
    "Windows",
    "Linux",
    "aria-pressed",
    "Shift+Tab",
    "screen reader",
    "clipboard success and failure",
    // The note must identify the platform controls and the copy control.
    "Choose an operating system",
    "View exact installer source",
    "platform installation guide",
    "Copy command:",
    // Concrete accessible-name checks.
    "aria-hidden",
    "accessibility tree",
    "distinct",
    // Concrete keyboard checks.
    "Enter and Space",
    "focus remains on the activated button",
    // Live-region copy feedback.
    "aria-live",
  ]) {
    assert.ok(review.includes(item), `missing review item: ${item}`);
  }
});
// Keep the colocated rendering tests in the normal web test suite as well.
for (const file of ["QuickStart.test.tsx", "quickstart-tempdir.test.tsx"]) {
  load(`components/landing/${file}`, { "./QuickStart": quickStart, "@/lib/public-release": release });
}
