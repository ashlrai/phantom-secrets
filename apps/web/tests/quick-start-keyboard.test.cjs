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
const { cleanup, render, screen, waitFor, within } = require("@testing-library/react");
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

test("platform controls show keyboard focus and select their instructions", async () => {
  const style = document.createElement("style");
  style.textContent = fs.readFileSync(path.join(__dirname, "../src/app/globals.css"), "utf8");
  document.head.appendChild(style);
  const user = userEvent.setup();
  render(React.createElement(QuickStart));
  try {
    const group = screen.getByRole("group", { name: "Choose an operating system" });
    const platforms = ["macOS", "Windows", "Linux"];
    const buttons = within(group).getAllByRole("button");
    assert.deepEqual(buttons.map((button) => button.textContent), platforms);
    await user.click(buttons[2]);
    document.activeElement.blur();

    for (const [index, platform] of platforms.entries()) {
      await user.tab();
      const button = buttons[index];
      assert.equal(document.activeElement, button, `${platform}: reachable by Tab in order`);
      assert.ok(button.matches(":focus-visible"), `${platform}: keyboard focus is visible`);
      // JSDOM caches styles across focus changes; reattach the stylesheet to recalculate them.
      style.remove();
      document.head.appendChild(style);
      const focusedStyle = window.getComputedStyle(button);
      assert.match(focusedStyle.outline, /^2px solid (?:#60a5fa|rgb\(96, 165, 250\))$/i, `${platform}: focus outline`);
      assert.equal(focusedStyle.outlineOffset, "2px", `${platform}: focus outline offset`);

      assert.equal(button.getAttribute("aria-pressed"), "false", `${platform}: initially unselected`);
      await user.keyboard(index === 1 ? " " : "{Enter}");
      assert.equal(document.activeElement, button, `${platform}: activation retains focus`);
      assert.equal(button.getAttribute("aria-pressed"), "true", `${platform}: selected`);
      assert.ok(screen.getByRole("heading", { level: 3, name: platform }), `${platform}: instructions displayed`);
      for (const other of buttons.filter((candidate) => candidate !== button)) {
        assert.equal(other.getAttribute("aria-pressed"), "false", `${platform}: other platforms unselected`);
      }
    }
  } finally {
    cleanup();
    style.remove();
  }
});

test("QuickStart copy controls are named, reachable by Tab, and operable by keyboard", async () => {
  for (const platform of ["macOS", "Windows", "Linux"]) {
    const user = userEvent.setup();
    render(React.createElement(QuickStart));
    try {
      await user.click(screen.getByRole("button", { name: platform }));
      document.activeElement.blur();
      const buttons = screen.getAllByRole("button", { name: /^Copy command:/ });
      assert.equal(buttons.length, 3, `${platform}: selected platform and setup steps have named copy buttons`);
      assert.equal(screen.getByRole("button", { name: "Copy command: phantom init" }), buttons[2]);

      const reached = [];
      for (let i = 0; i < 40 && reached.length < buttons.length; i++) {
        await user.tab();
        if (buttons.includes(document.activeElement)) reached.push(document.activeElement);
      }
      assert.deepEqual(reached, buttons, `${platform}: Tab reaches every copy button in document order`);

      for (const key of ["{Enter}", " "]) {
        await navigator.clipboard.writeText("");
        await user.keyboard(key);
        await waitFor(async () => assert.equal(await navigator.clipboard.readText(), "phantom init"));
        assert.equal(document.activeElement, buttons[2], "copying keeps focus on the control");
      }
    } finally {
      cleanup();
    }
  }
});
