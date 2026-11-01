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
const { cleanup, fireEvent, render, screen, within } = require("@testing-library/react");

function load(file, dependencies = {}) {
  const source = fs.readFileSync(path.join(__dirname, "../src", file), "utf8");
  const compiled = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
  }).outputText;
  const exports = {};
  new Function("exports", "require", compiled)(exports, (name) => dependencies[name] ?? require(name));
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

const root = path.join(__dirname, "../../..");
const guide = fs.readFileSync(path.join(root, "docs/quickstart-platform-sections.md"), "utf8");

function blocks(section) {
  const heading = `## ${section}\n`;
  assert.ok(guide.includes(heading), `missing section: ${section}`);
  const content = guide.split(heading)[1].split(/^## /m)[0];
  return [...content.matchAll(/^\s*```(?:bash|powershell)\n([\s\S]*?)^\s*```/gm)]
    .map((match) => match[1].replace(/^ {3}/gm, "").replace(/\n$/, ""));
}

function commandText(button) {
  return [...button.firstElementChild.childNodes]
    .filter((node) => node.nodeType === Node.TEXT_NODE)
    .map((node) => node.textContent)
    .join("");
}

test("platform sections match the selectable cards and their displayed commands", () => {
  const { container } = render(React.createElement(QuickStart));
  try {
    const selector = screen.getByRole("group", { name: "Choose an operating system" });
    const platforms = within(selector).getAllByRole("button");
    assert.deepEqual(platforms.map((button) => button.textContent), ["macOS", "Windows", "Linux"]);
    assert.deepEqual([...guide.matchAll(/^## (.+)$/gm)].map((match) => match[1]),
      [...platforms.map((button) => button.textContent), "Shared numbered steps"]);
    assert.equal(platforms[0].getAttribute("aria-pressed"), "true");

    for (const button of platforms) {
      fireEvent.click(button);
      const platform = button.textContent;
      const card = container.querySelector(".platform-install-card");
      assert.equal(container.querySelectorAll(".platform-install-card").length, 1);
      assert.equal(within(card).getByRole("heading", { level: 3 }).textContent, platform);
      assert.equal(within(card).getByText("Download, verify, install, and check both binaries").tagName, "STRONG");
      const command = within(card.querySelector(".platform-install-card__command")).getByRole("button");
      assert.deepEqual(blocks(platform), [commandText(command)], `${platform} command differs from the page`);
      assert.equal(command.querySelector('[aria-hidden="true"]').textContent.trim(), platform === "Windows" ? "PS>" : "$");
      for (const architecture of within(card.querySelector(".platform-install-card__targets")).getAllByRole("link", { name: /^Download Phantom / })) {
        assert.ok(guide.split(`## ${platform}\n`)[1].split(/^## /m)[0].includes(architecture.textContent.split("archive")[0]),
          `${platform} architecture missing from guide`);
      }
    }
  } finally {
    cleanup();
  }
});

test("shared command blocks and documentation index stay in sync", () => {
  const { container } = render(React.createElement(QuickStart));
  try {
    const steps = container.querySelector(".passage-steps");
    const buttons = within(steps).getAllByRole("button");
    assert.deepEqual(blocks("Shared numbered steps"), buttons.map(commandText));
    for (const heading of within(steps).getAllByRole("heading", { level: 3 })) {
      assert.ok(guide.includes(heading.textContent), `missing shared step: ${heading.textContent}`);
    }
    assert.match(fs.readFileSync(path.join(root, "docs/README.md"), "utf8"), /\]\(quickstart-platform-sections\.md\)/);
  } finally {
    cleanup();
    dom.window.close();
  }
});
