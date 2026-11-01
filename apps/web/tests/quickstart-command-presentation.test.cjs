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
const { cleanup, fireEvent, render, screen, within, waitFor } = require("@testing-library/react");

function load(file, dependencies = {}) {
  const source = fs.readFileSync(path.join(__dirname, "../src", file), "utf8");
  const compiled = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
  }).outputText;
  const exports = {};
  new Function("exports", "require", compiled)(exports, (name) => dependencies[name] ?? require(name));
  return exports;
}

const icons = load("components/landing/Icons.tsx");
const copy = load("components/landing/CopyButton.tsx", {
  "./Icons": icons,
  "@/lib/posthog": { capturePostHog: async () => {} },
});
const { QuickStart } = load("components/landing/QuickStart.tsx", {
  "./CopyButton": copy,
  "@/lib/public-release": load("lib/public-release.ts"),
  "next/link": { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) },
});

test("installer and numbered controls appear in order and copy only their commands", async () => {
  const writes = [];
  Object.defineProperty(navigator, "clipboard", { value: { writeText: async (text) => writes.push(text) }, configurable: true });
  const { container } = render(React.createElement(QuickStart));
  try {
    const selector = screen.getByRole("group", { name: "Choose an operating system" });
    assert.equal(within(selector).getByRole("button", { name: "macOS" }).getAttribute("aria-pressed"), "true");
    const steps = container.querySelector(".passage-steps");
    assert.equal(steps.querySelectorAll("li").length, 2);
    const stepButtons = within(steps).getAllByRole("button");
    assert.equal(stepButtons.length, 2);
    assert.deepEqual([...steps.querySelectorAll(".passage-steps__receipt > span")].map((node) => node.textContent),
      ["illustrative receipt", "illustrative receipt"]);

    for (const [platform, prompt] of [["macOS", "$"], ["Windows", "PS>"], ["Linux", "$"]]) {
      fireEvent.click(within(selector).getByRole("button", { name: platform }));
      const card = container.querySelector(".platform-install-card");
      assert.equal(container.querySelectorAll(".platform-install-card").length, 1);
      assert.equal(within(card).getByRole("heading", { level: 3 }).textContent, platform);
      assert.ok(card.compareDocumentPosition(steps) & Node.DOCUMENT_POSITION_FOLLOWING);
      const command = within(card.querySelector(".platform-install-card__command")).getByRole("button");
      assert.equal(command.querySelector('[aria-hidden="true"]').textContent.trim(), prompt);
      fireEvent.click(command);
      await waitFor(() => assert.equal(writes.length, ["macOS", "Windows", "Linux"].indexOf(platform) + 1));
      assert.equal(writes.at(-1), command.firstElementChild.lastChild.textContent);
    }
    for (const [index, expected] of ["phantom --version\nphantom-mcp --version", "phantom init"].entries()) {
      assert.equal(stepButtons[index].querySelector('[aria-hidden="true"]').textContent.trim(), "$");
      fireEvent.click(stepButtons[index]);
      await waitFor(() => assert.equal(writes.length, 4 + index));
      assert.equal(writes.at(-1), expected);
    }
  } finally {
    cleanup();
    dom.window.close();
  }
});

test("presentation guide is discoverable and describes the styled controls", () => {
  const root = path.join(__dirname, "../../..");
  const guide = fs.readFileSync(path.join(root, "docs/quickstart-command-presentation.md"), "utf8");
  const css = fs.readFileSync(path.join(root, "apps/web/src/app/globals.css"), "utf8");
  assert.match(fs.readFileSync(path.join(root, "docs/README.md"), "utf8"), /\]\(quickstart-command-presentation\.md\)/);
  for (const phrase of ["macOS is selected initially", "Windows and Linux", "`PS>`", "`$`", "on PATH", "illustrative", "clipboard without the decorative prompt", "receipt moves below"]) {
    assert.ok(guide.includes(phrase), `guide describes ${phrase}`);
  }
  assert.match(css, /\.copy-command\s*\{[^}]*background:\s*rgba\(255, 255, 255, 0\.76\)/s);
  assert.match(css, /\.platform-install-card__command \.copy-command\s*\{[^}]*min-height:\s*12rem;[^}]*background:\s*#071018;[^}]*font-size:\s*0\.62rem/s);
  assert.match(css, /\.passage-steps__receipt\s*\{\s*grid-column:\s*2;\s*border-top:/s);
});
