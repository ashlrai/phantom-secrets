import assert from "node:assert/strict";
import test from "node:test";
import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QuickStart } from "./QuickStart";
import { PUBLIC_RELEASE_TAG } from "@/lib/public-release";

const normalize = (value: string) => value.replace(/\s+/g, " ").trim();

test("each displayed platform option has a distinct accessible name", async () => {
  const user = userEvent.setup();
  render(<QuickStart />);
  try {
    const selector = screen.getByRole("group", { name: "Choose an operating system" });
    const platforms = ["macOS", "Windows", "Linux"];

    for (const selected of platforms) {
      await user.click(within(selector).getByRole("button", { name: selected }));
      const buttons = within(selector).getAllByRole("button");
      const displayedNames = buttons.map((button) => normalize(button.textContent ?? ""));
      assert.deepEqual(displayedNames, platforms);
      assert.equal(new Set(displayedNames).size, buttons.length);
      for (const [index, name] of displayedNames.entries()) {
        // getByRole requires exactly one button with this computed accessible name.
        assert.equal(within(selector).getByRole("button", { name }), buttons[index]);
      }
      assert.equal(within(selector).getByRole("button", { name: selected, pressed: true }), buttons[platforms.indexOf(selected)]);
    }
  } finally {
    cleanup();
  }
});

test("all installation controls and links remain named for each platform", async () => {
  const user = userEvent.setup();
  render(<QuickStart />);
  try {
    const region = screen.getByRole("region", { name: "Install on your OS. Then protect one project." });
    const selector = within(region).getByRole("group", { name: "Choose an operating system" });

    for (const platform of ["macOS", "Windows", "Linux"]) {
      await user.click(within(selector).getByRole("button", { name: platform }));
      const buttons = within(region).getAllByRole("button");
      assert.equal(buttons.length, 6, `${platform}: three platform and three copy controls`);
      assert.deepEqual(within(region).getAllByRole("button", { name: /\S/ }), buttons);
      assert.equal(within(region).getAllByRole("button", { name: /^Copy command: \S/ }).length, 3);

      const links = within(region).getAllByRole("link");
      assert.ok(links.length > 0);
      assert.deepEqual(within(region).getAllByRole("link", { name: /\S/ }), links);
    }
  } finally {
    cleanup();
  }
});

test("installation examples and download links have accessible names on every platform", async () => {
  const user = userEvent.setup();
  render(<QuickStart />);
  try {
    const selector = screen.getByRole("group", { name: "Choose an operating system" });
    const cases = [
      { name: "macOS", targets: ["Apple Silicon", "Intel"], command: /shasum -a 256 -c -/ },
      { name: "Windows", targets: ["ARM64", "x64"], command: /Get-FileHash -Algorithm SHA256/ },
      { name: "Linux", targets: ["ARM64", "x64"], command: /sha256sum -c -/ },
    ];

    for (const platform of cases) {
      await user.click(within(selector).getByRole("button", { name: platform.name }));
      assert.ok(within(selector).getByRole("button", { name: platform.name, pressed: true }));
      const card = screen.getByRole("heading", { level: 3, name: platform.name }).closest("article");
      assert.ok(card);
      for (const target of platform.targets) {
        assert.ok(within(card).getByRole("link", {
          name: `Download Phantom ${PUBLIC_RELEASE_TAG} for ${platform.name} ${target}`,
        }));
        assert.ok(within(card).getByRole("link", {
          name: `Download the SHA-256 checksum for Phantom ${PUBLIC_RELEASE_TAG} on ${platform.name} ${target}`,
        }));
      }

      const copy = within(card).getByRole("button", { name: /^Copy command:/ });
      assert.match(copy.textContent ?? "", platform.command);
      await user.click(copy);
      const copied = await navigator.clipboard.readText();
      assert.match(copied, platform.command);
      // The accessible name must include the entire displayed command, not just a generic label.
      assert.equal(within(card).getByRole("button", {
        name: (name) => normalize(name).startsWith("Copy command: ") && normalize(name).includes(normalize(copied)),
      }), copy);
    }
  } finally {
    cleanup();
  }
});

test("follow-up examples have distinct named copy controls and copy their commands", async () => {
  const user = userEvent.setup();
  render(<QuickStart />);
  try {
    for (const [heading, command] of [
      [`Verify both ${PUBLIC_RELEASE_TAG} binaries`, "phantom --version\nphantom-mcp --version"],
      ["Protect one supported project", "phantom init"],
    ]) {
      const step = screen.getByRole("heading", { level: 3, name: heading }).closest("li");
      assert.ok(step);
      const copy = within(step).getByRole("button", { name: (name) => normalize(name) === `Copy command: ${normalize(command)}` });
      await user.click(copy);
      assert.equal(await navigator.clipboard.readText(), command);
      assert.equal(document.activeElement, copy);
      assert.equal(within(copy).getByText("Copied").getAttribute("aria-live"), "polite");
    }
  } finally {
    cleanup();
  }
});
