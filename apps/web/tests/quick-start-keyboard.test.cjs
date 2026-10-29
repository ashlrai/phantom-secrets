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
const { cleanup, fireEvent, render, screen, waitFor, within } = require("@testing-library/react");
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

test("quick start remains a region named by its visible heading when switching platforms", async () => {
  const user = userEvent.setup();
  render(React.createElement(QuickStart));
  try {
    const name = "Install on your OS. Then protect one project.";
    const region = screen.getByRole("region", { name });
    const heading = within(region).getByRole("heading", { level: 2, name });
    assert.equal(region.getAttribute("aria-labelledby"), heading.id);
    assert.ok(heading.id);

    for (const platform of ["Windows", "Linux", "macOS"]) {
      await user.click(within(region).getByRole("button", { name: platform }));
      assert.equal(screen.getByRole("region", { name }), region);
      assert.equal(within(region).getByRole("heading", { level: 2, name }), heading);
      assert.ok(within(region).getByRole("heading", { level: 3, name: platform }));
    }
  } finally {
    cleanup();
  }
});

test("reduced motion keeps platform commands available without animation events", async () => {
  const originalMatchMedia = window.matchMedia;
  window.matchMedia = (query) => ({
    matches: query === "(prefers-reduced-motion: reduce)",
    media: query,
    addEventListener() {},
    removeEventListener() {},
    addListener() {},
    removeListener() {},
  });
  const user = userEvent.setup();
  try {
    render(React.createElement(QuickStart));
    const selector = screen.getByRole("group", { name: "Choose an operating system" });
    const check = (platform, commandPart) => {
      const active = within(selector).getByRole("button", { name: platform });
      for (const button of within(selector).getAllByRole("button")) {
        assert.equal(button.getAttribute("aria-pressed"), String(button === active));
      }
      const card = screen.getByRole("heading", { level: 3, name: platform }).closest("article");
      assert.ok(card);
      assert.equal(document.querySelectorAll(".platform-install-card").length, 1);
      const command = within(card).getByRole("button", { name: /^Copy command:/ });
      assert.ok(command.textContent.includes(commandPart), `${platform}: command is immediately available`);
      assert.equal(command.disabled, false);
      return command;
    };

    check("macOS", "shasum -a 256 -c -");
    // Dispatch no animation or transition events: selection must update on activation alone.
    fireEvent.click(within(selector).getByRole("button", { name: "Windows" }));
    check("Windows", "Get-FileHash -Algorithm SHA256");
    const linux = within(selector).getByRole("button", { name: "Linux" });
    linux.focus();
    await user.keyboard("{Enter}");
    assert.equal(document.activeElement, linux);
    const command = check("Linux", "sha256sum -c -");
    await user.click(command);
    assert.ok((await navigator.clipboard.readText()).includes("sha256sum -c -"));
    fireEvent.click(within(selector).getByRole("button", { name: "macOS" }));
    check("macOS", "shasum -a 256 -c -");
  } finally {
    cleanup();
    window.matchMedia = originalMatchMedia;
  }
});

test("re-selecting the active platform preserves its selection and install command", async () => {
  const user = userEvent.setup();
  render(React.createElement(QuickStart));
  try {
    const selector = screen.getByRole("group", { name: "Choose an operating system" });
    for (const [platform, commandPart] of [
      ["macOS", "shasum -a 256 -c -"],
      ["Windows", "Get-FileHash -Algorithm SHA256"],
      ["Linux", "sha256sum -c -"],
      ["macOS", "shasum -a 256 -c -"],
    ]) {
      const active = within(selector).getByRole("button", { name: platform });
      if (active.getAttribute("aria-pressed") !== "true") await user.click(active);
      const card = screen.getByRole("heading", { level: 3, name: platform }).closest("article");
      assert.ok(card);
      const command = within(card).getByRole("button", { name: /^Copy command:/ });
      const displayed = command.textContent;
      assert.ok(displayed.includes(commandPart), `${platform}: expected install command`);

      for (let repeat = 0; repeat < 2; repeat++) {
        await user.click(active);
        for (const button of within(selector).getAllByRole("button")) {
          assert.equal(button.getAttribute("aria-pressed"), String(button === active));
        }
        assert.equal(screen.getByRole("heading", { level: 3, name: platform }).closest("article"), card);
        assert.equal(within(card).getByRole("button", { name: /^Copy command:/ }).textContent, displayed);
      }

      await user.click(command);
      const copied = await navigator.clipboard.readText();
      assert.ok(copied.includes(commandPart), `${platform}: copied command matches the displayed platform`);
      assert.ok(displayed.includes(copied), `${platform}: copied command matches the displayed command`);
    }
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

      const commandNode = Array.from(buttons[0].firstElementChild.childNodes)
        .find((node) => node.nodeType === dom.window.Node.TEXT_NODE);
      assert.ok(commandNode, `${platform}: install command is text`);
      const range = document.createRange();
      range.selectNodeContents(commandNode);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      const selectedCommand = selection.toString();
      assert.ok(selectedCommand.includes("\n"), `${platform}: selection includes line breaks`);
      await user.click(buttons[0]);
      await waitFor(async () => assert.equal(await navigator.clipboard.readText(), selectedCommand));
      selection.removeAllRanges();
      document.activeElement.blur();

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
