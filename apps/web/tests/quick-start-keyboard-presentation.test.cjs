// Verify keyboard focus and activation for the rendered platform controls.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { JSDOM } = require("jsdom");
const ts = require("typescript");

const dom = new JSDOM("<!doctype html><html><body></body></html>", { url: "http://localhost/" });
global.window = dom.window;
global.document = dom.window.document;
global.Node = dom.window.Node;
global.HTMLElement = dom.window.HTMLElement;
Object.defineProperty(global, "navigator", { value: dom.window.navigator, configurable: true });

const React = require("react");
const { cleanup, render, screen, within } = require("@testing-library/react");
const userEvent = require("@testing-library/user-event").default;

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

test("platform selection exposes exactly one pressed button after each click", async () => {
  const user = userEvent.setup();
  render(React.createElement(QuickStart));
  try {
    const selector = screen.getByRole("group", { name: "Choose an operating system" });
    const names = ["macOS", "Windows", "Linux"];
    const assertSelection = (selected) => {
      assert.deepEqual(
        within(selector).getAllByRole("button", { pressed: true }).map((button) => button.textContent),
        [selected],
      );
      assert.deepEqual(
        within(selector).getAllByRole("button", { pressed: false }).map((button) => button.textContent),
        names.filter((name) => name !== selected),
      );
      assert.equal(screen.getAllByRole("article").length, 1);
      assert.ok(screen.getByRole("heading", { level: 3, name: selected }).closest("article"));
    };

    assertSelection("macOS");
    for (const selected of ["Windows", "Linux", "Linux", "macOS"]) {
      await user.click(within(selector).getByRole("button", { name: selected }));
      assertSelection(selected);
    }
  } finally {
    cleanup();
  }
});

test("keyboard focus reaches every platform control and Enter or Space activates it", async () => {
  const user = userEvent.setup();
  render(React.createElement(QuickStart));
  try {
    const selector = screen.getByRole("group", { name: "Choose an operating system" });
    const names = ["macOS", "Windows", "Linux"];
    const controls = names.map((name) => within(selector).getByRole("button", { name }));
    assert.equal(within(selector).getAllByRole("button").length, controls.length);
    const pressed = (selected) => assert.deepEqual(
      controls.map((control) => control.getAttribute("aria-pressed")),
      names.map((name) => String(name === selected)),
      `${selected}: exactly one pressed control`,
    );

    // Every platform control takes keyboard focus in display order, and the
    // next Tab stop is inside the selected platform's card.
    for (const control of controls) {
      await user.tab();
      assert.equal(document.activeElement, control, `${control.textContent}: Tab focus`);
    }
    const macCard = screen.getByRole("heading", { level: 3, name: "macOS" }).closest("article");
    await user.tab();
    assert.equal(document.activeElement, within(macCard).getAllByRole("link")[0],
      "Tab moves into the selected platform card");
    for (const control of [...controls].reverse()) {
      await user.tab({ shift: true });
      assert.equal(document.activeElement, control, `${control.textContent}: Shift+Tab focus`);
    }
    await user.tab({ shift: true });
    assert.ok(!selector.contains(document.activeElement), "focus is not trapped in the selector");

    // Enter on a focused control selects its platform, swaps the card, and
    // keeps focus on the control so keyboard users stay oriented.
    pressed("macOS");
    await user.tab();
    await user.tab();
    assert.equal(document.activeElement, controls[1]);
    await user.keyboard("{Enter}");
    assert.equal(document.activeElement, controls[1], "focus remains on the activated control");
    pressed("Windows");
    const windowsCard = screen.getByRole("heading", { level: 3, name: "Windows" }).closest("article");
    assert.ok(windowsCard);
    assert.equal(screen.queryByRole("heading", { level: 3, name: "macOS" }), null, "the previous card is replaced");
    // The remaining controls precede the card, so Tab reaches Linux before the card.
    await user.tab();
    assert.equal(document.activeElement, controls[2]);
    await user.tab();
    assert.equal(document.activeElement, within(windowsCard).getAllByRole("link")[0],
      "keyboard users reach the newly displayed card");
    await user.tab({ shift: true });
    assert.equal(document.activeElement, controls[2]);

    // Space activates a focused control the same way.
    await user.keyboard(" ");
    assert.equal(document.activeElement, controls[2], "focus remains on the activated control");
    pressed("Linux");
    assert.ok(screen.getByRole("heading", { level: 3, name: "Linux" }));

    // Returning to an earlier control still activates it from the keyboard.
    await user.tab({ shift: true });
    await user.tab({ shift: true });
    assert.equal(document.activeElement, controls[0]);
    await user.keyboard("{Enter}");
    assert.equal(document.activeElement, controls[0]);
    pressed("macOS");
    assert.ok(screen.getByRole("heading", { level: 3, name: "macOS" }));
    assert.equal(screen.queryByRole("heading", { level: 3, name: "Linux" }), null);
  } finally {
    cleanup();
  }
});

for (const key of ["{Enter}", " "]) {
  for (const [name, archive, command] of [
    ["macOS", "Apple Silicon", "shasum -a 256 -c -"],
    ["Windows", "ARM64", "Get-FileHash -Algorithm SHA256"],
    ["Linux", "ARM64", "sha256sum -c -"],
  ]) {
    test(`${name} presents its install instructions after keyboard activation with ${key === " " ? "Space" : "Enter"}`, async () => {
      const user = userEvent.setup();
      render(React.createElement(QuickStart));
      try {
        const selector = screen.getByRole("group", { name: "Choose an operating system" });
        const controls = within(selector).getAllByRole("button");
        const target = within(selector).getByRole("button", { name });

        // Start with a different selection, including for the default platform.
        if (name === "macOS") {
          await user.tab();
          await user.tab();
          await user.keyboard("{Enter}");
          await user.tab({ shift: true });
        } else {
          for (let i = 0; i <= controls.indexOf(target); i++) await user.tab();
        }
        assert.equal(document.activeElement, target);
        assert.equal(target.getAttribute("aria-pressed"), "false");

        await user.keyboard(key);
        assert.equal(document.activeElement, target);
        for (const control of controls) {
          assert.equal(control.getAttribute("aria-pressed"), String(control === target));
        }
        const cards = screen.getAllByRole("article");
        assert.equal(cards.length, 1);
        const card = cards[0];
        assert.ok(within(card).getByRole("heading", { level: 3, name }));
        const download = within(card).getByRole("link", { name: new RegExp(`^Download Phantom .* for ${name} ${archive}$`) });
        assert.ok(within(card).getByRole("button", { name: /^Copy command:/ }).textContent.includes(command));

        // Tab from the activated button through remaining choices to its card.
        for (let i = controls.indexOf(target); i < controls.length; i++) await user.tab();
        assert.equal(document.activeElement, download);
      } finally {
        cleanup();
      }
    });
  }
}
