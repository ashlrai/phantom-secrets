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

test("each platform displays and copies its phantom-install staging prefix", async () => {
  const user = userEvent.setup();
  render(React.createElement(QuickStart));
  try {
    const expected = [
      ["macOS", 'phantom_stage="$(mktemp -d "${TMPDIR:-/tmp}/phantom-install.XXXXXX")"'],
      ["Windows", `$Installer = Join-Path $env:TEMP ('phantom-install-${release.PUBLIC_RELEASE_TAG}-{0}.ps1' -f [Guid]::NewGuid().ToString('N'))`],
      ["Linux", 'phantom_stage="$(mktemp -d "${TMPDIR:-/tmp}/phantom-install.XXXXXX")"'],
    ];
    const selector = screen.getByRole("group", { name: "Choose an operating system" });
    assert.equal(within(selector).getAllByRole("button").length, expected.length);
    for (const [platform, stagingLine] of expected) {
      await user.click(within(selector).getByRole("button", { name: platform }));
      const card = screen.getByRole("heading", { level: 3, name: platform }).closest("article");
      const button = within(card).getByRole("button", { name: /^Copy command:/ });
      assert.ok(button.textContent.includes(stagingLine), `${platform}: displayed staging path`);
      await user.click(button);
      const copied = await navigator.clipboard.readText();
      assert.ok(copied.split("\n").includes(stagingLine), `${platform}: copied staging path`);
    }
  } finally {
    cleanup();
  }
});

test("QuickStart displays line breaks between consecutive commands", async () => {
  const style = document.createElement("style");
  style.textContent = fs.readFileSync(path.join(__dirname, "../src/app/globals.css"), "utf8");
  document.head.append(style);
  const user = userEvent.setup();
  try {
    render(React.createElement(QuickStart));
    for (const [platform, consecutiveCommands] of [
      ["macOS", "set -euo pipefail\numask 077"],
      ["Windows", "  & $Installer\n  if (-not $?) { throw 'Phantom installer failed' }"],
      ["Linux", "set -euo pipefail\numask 077"],
    ]) {
      await user.click(screen.getByRole("button", { name: platform }));
      const card = screen.getByRole("heading", { level: 3, name: platform }).closest("article");
      const installText = within(card).getByRole("button", { name: /^Copy command:/ }).firstElementChild;
      const versionText = within(screen.getByRole("list", { name: "" }))
        .getAllByRole("button", { name: /^Copy command:/ })[0].firstElementChild;

      for (const [label, element, expected] of [
        [platform, installText, consecutiveCommands],
        ["version check", versionText, "phantom --version\nphantom-mcp --version"],
      ]) {
        assert.ok(element.textContent.includes(expected), `${label}: consecutive commands retain their newline`);
        assert.equal(window.getComputedStyle(element).whiteSpace, "pre-wrap", `${label}: newlines are displayed`);
      }
    }
  } finally {
    cleanup();
    style.remove();
  }
});

test("every displayed QuickStart command can be selected and matches the copied text", async () => {
  const style = document.createElement("style");
  style.textContent = fs.readFileSync(path.join(__dirname, "../src/app/globals.css"), "utf8");
  document.head.append(style);
  const user = userEvent.setup();
  try {
    render(React.createElement(QuickStart));
    for (const [platform, installPart] of [
      ["macOS", "shasum -a 256 -c -"],
      ["Windows", "Get-FileHash -Algorithm SHA256"],
      ["Linux", "sha256sum -c -"],
    ]) {
      await user.click(screen.getByRole("button", { name: platform }));
      const buttons = screen.getAllByRole("button", { name: /^Copy command:/ });
      assert.equal(buttons.length, 3, `${platform}: install and both follow-up commands are displayed`);
      for (const [index, button] of buttons.entries()) {
        const textContainer = button.firstElementChild;
        const textNodes = Array.from(textContainer.childNodes).filter((node) => node.nodeType === dom.window.Node.TEXT_NODE);
        assert.equal(textNodes.length, 1, `${platform}: command ${index + 1} is selectable text`);
        const command = textNodes[0].textContent;
        assert.ok(command, `${platform}: command ${index + 1} is not empty`);
        assert.equal(window.getComputedStyle(textContainer).userSelect, "text");
        assert.equal(window.getComputedStyle(textContainer).whiteSpace, "pre-wrap");
        if (index === 0) assert.ok(command.includes(installPart), `${platform}: expected installer`);
        if (index === 1) assert.equal(command, "phantom --version\nphantom-mcp --version");
        if (index === 2) assert.equal(command, "phantom init");

        const selection = window.getSelection();
        const range = document.createRange();
        range.selectNodeContents(textNodes[0]);
        selection.removeAllRanges();
        selection.addRange(range);
        assert.equal(selection.toString(), command, `${platform}: selection preserves the entire command`);
        await user.click(button);
        await waitFor(async () => assert.equal(await navigator.clipboard.readText(), command));
        selection.removeAllRanges();
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
