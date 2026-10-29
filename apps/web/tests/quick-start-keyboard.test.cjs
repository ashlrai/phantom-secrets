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

test("the initial macOS instructions display and copy their install command", async () => {
  const user = userEvent.setup();
  render(React.createElement(QuickStart));
  try {
    assert.equal(screen.getByRole("button", { name: "macOS" }).getAttribute("aria-pressed"), "true");
    const card = screen.getByRole("heading", { name: "macOS" }).closest("article");
    assert.ok(card);
    const instructions = within(card);
    assert.ok(instructions.getByText("Uses Keychain when available. The verified source installer auto-detects Apple Silicon or Intel."));
    assert.ok(instructions.getByRole("link", { name: `Download Phantom ${release.PUBLIC_RELEASE_TAG} for macOS Apple Silicon` }));

    const source = instructions.getByRole("link", { name: "View exact installer source" }).getAttribute("href");
    const copy = instructions.getByRole("button", { name: /^Copy command:/ });
    const command = Array.from(copy.firstElementChild.childNodes)
      .filter((node) => node.nodeType === dom.window.Node.TEXT_NODE)
      .map((node) => node.textContent)
      .join("");
    assert.ok(command.includes(source), "the displayed command downloads the linked installer");
    assert.ok(command.includes(release.PUBLIC_RELEASE_UNIX_INSTALLER_SHA256));
    assert.ok(command.includes("shasum -a 256 -c -"), "the command uses the macOS checksum utility");
    assert.ok(command.includes('"$HOME/.phantom-secrets/bin/phantom-mcp" --version'));
    assert.ok(!command.includes("sha256sum -c -"));
    assert.ok(!command.includes("Get-FileHash"));

    await user.click(copy);
    await waitFor(async () => assert.equal(await navigator.clipboard.readText(), command));
  } finally {
    cleanup();
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
