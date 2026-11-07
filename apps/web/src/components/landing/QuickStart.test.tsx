import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { QuickStart } from "./QuickStart";
import { PUBLIC_RELEASE_RECEIPT, PUBLIC_RELEASE_TAG } from "@/lib/public-release";

test("quick-start section presents its title as a heading", () => {
  render(<QuickStart />);
  try {
    const title = "Install on your OS. Then protect one project.";
    const heading = screen.getByRole("heading", { level: 2, name: title });
    const section = screen.getByRole("region", { name: title });

    assert.equal(heading.textContent, title);
    assert.ok(section.contains(heading));
    assert.equal(section.getAttribute("aria-labelledby"), heading.id);
  } finally {
    cleanup();
  }
});

test("the quick-start heading labels the installation content for every platform", () => {
  render(<QuickStart />);
  try {
    const title = "Install on your OS. Then protect one project.";
    const section = screen.getByRole("region", { name: title });
    const heading = within(section).getByRole("heading", { level: 2, name: title });
    const selector = within(section).getByRole("group", { name: "Choose an operating system" });

    assert.equal(section.tagName, "SECTION");
    assert.equal(section.id, "install");
    assert.ok(heading.id);
    assert.equal(section.getAttribute("aria-labelledby"), heading.id);
    assert.equal(Array.from(document.querySelectorAll("[id]")).filter((element) => element.id === heading.id).length, 1);

    for (const platform of ["macOS", "Windows", "Linux"]) {
      fireEvent.click(within(selector).getByRole("button", { name: platform }));
      assert.equal(screen.getByRole("region", { name: title }), section);
      assert.equal(within(section).getByRole("heading", { level: 2, name: title }), heading);
      assert.ok(within(section).getByRole("heading", { level: 3, name: platform }));
      assert.ok(within(section).getByRole("link", { name: "View exact installer source" }));
      assert.ok(within(section).getByRole("heading", { level: 3, name: "Protect one supported project" }));
    }
  } finally {
    cleanup();
  }
});

test("rendered installation instructions keep their order for every platform", () => {
  render(<QuickStart />);
  try {
    const section = screen.getByRole("region", { name: "Install on your OS. Then protect one project." });
    const selector = within(section).getByRole("group", { name: "Choose an operating system" });
    const list = within(section).getByRole("list");
    const steps = within(list).getAllByRole("listitem");
    const expected = [
      {
        number: "01",
        heading: `Verify both ${PUBLIC_RELEASE_TAG} binaries`,
        description: "After the platform-specific install, confirm that the CLI and MCP server report the pinned public version.",
        command: "phantom --version\nphantom-mcp --version",
        receipt: PUBLIC_RELEASE_RECEIPT,
      },
      {
        number: "02",
        heading: "Protect one supported project",
        description: "From an owned Git repository, keep an independent provider recovery copy and begin with a supported HTTP API key—not a database connection string.",
        command: "phantom init",
        receipt: "vault write completed\nmanaged dotenv rewritten\nno plaintext project backup",
      },
    ];

    assert.equal(steps.length, expected.length);
    for (const [index, step] of steps.entries()) {
      const item = expected[index];
      assert.equal(step.querySelector("[aria-hidden='true']")?.textContent?.trim(), item.number);
      assert.equal(within(step).getByRole("heading", { level: 3 }).textContent, item.heading);
      assert.ok(within(step).getByText(item.description));
      const command = within(step).getByRole("button", { name: /^Copy command:/ });
      const text = Array.from(command.firstElementChild!.childNodes)
        .filter((node) => node.nodeType === Node.TEXT_NODE)
        .map((node) => node.textContent)
        .join("");
      assert.equal(text, item.command);
      assert.equal(within(step).getByText("illustrative receipt").nextElementSibling?.textContent, item.receipt);
    }

    for (const platform of ["macOS", "Windows", "Linux"]) {
      fireEvent.click(within(selector).getByRole("button", { name: platform }));
      const card = within(section).getByRole("heading", { level: 3, name: platform }).closest("article");
      assert.ok(card);
      assert.ok(within(card).getByText("Download, verify, install, and check both binaries"));
      assert.ok(card.compareDocumentPosition(list) & Node.DOCUMENT_POSITION_FOLLOWING, `${platform}: install comes before the numbered steps`);
      assert.deepEqual(within(list).getAllByRole("heading", { level: 3 }).map((heading) => heading.textContent), expected.map((item) => item.heading));
    }
  } finally {
    cleanup();
  }
});

test("Unix installation examples display a temporary staging directory", () => {
  render(<QuickStart />);
  try {
    const selector = screen.getByRole("group", { name: "Choose an operating system" });
    assert.equal(within(selector).getByRole("button", { name: "macOS" }).getAttribute("aria-pressed"), "true");
    for (const [platform, checksum] of [
      ["macOS", "shasum -a 256 -c -"],
      ["Linux", "sha256sum -c -"],
    ]) {
      fireEvent.click(within(selector).getByRole("button", { name: platform }));
      assert.equal(within(selector).getByRole("button", { name: platform }).getAttribute("aria-pressed"), "true");
      const card = screen.getByRole("heading", { level: 3, name: platform }).closest("article");
      assert.ok(card);
      const command = within(card).getByRole("button", { name: /^Copy command:/ });
      // The command is rendered as text; this test never evaluates it in a shell.
      const displayed = Array.from(command.firstElementChild!.childNodes)
        .filter((node) => node.nodeType === Node.TEXT_NODE)
        .map((node) => node.textContent)
        .join("");
      assert.ok(displayed.includes('phantom_stage="$(mktemp -d "${TMPDIR:-/tmp}/phantom-install.XXXXXX")"'));
      assert.ok(displayed.includes('phantom_installer="$phantom_stage/install.sh"'));
      assert.ok(displayed.includes(`trap 'rm -f -- "$phantom_installer"; rmdir -- "$phantom_stage" 2>/dev/null || true' EXIT`));
      const download = displayed.indexOf("curl --fail");
      const verify = displayed.indexOf(checksum);
      const install = displayed.indexOf('bash "$phantom_installer"');
      assert.ok(download >= 0 && download < verify && verify < install, `${platform}: download, verify, then install`);
    }
  } finally {
    cleanup();
  }
});

test("Windows installation example displays a temporary installer file", () => {
  render(<QuickStart />);
  try {
    fireEvent.click(screen.getByRole("button", { name: "Windows" }));
    const card = screen.getByRole("heading", { level: 3, name: "Windows" }).closest("article");
    assert.ok(card);
    const command = within(card).getByRole("button", { name: /^Copy command:/ }).textContent ?? "";
    assert.match(command, /\$Installer = Join-Path \$env:TEMP/);
    assert.match(command, /Get-FileHash -Algorithm SHA256 -LiteralPath \$Installer/);
    assert.match(command, /Remove-Item -LiteralPath \$Installer -Force/);
  } finally {
    cleanup();
  }
});

test("every displayed quick-start command is selectable text without its prompt", () => {
  const style = document.createElement("style");
  style.textContent = fs.readFileSync(path.join(process.cwd(), "src/app/globals.css"), "utf8");
  document.head.append(style);
  render(<QuickStart />);
  try {
    for (const platform of ["macOS", "Windows", "Linux"]) {
      fireEvent.click(screen.getByRole("button", { name: platform }));
      const buttons = screen.getAllByRole("button", { name: /^Copy command:/ });
      assert.equal(buttons.length, 3, `${platform}: install and both follow-up commands are shown`);
      for (const button of buttons) {
        const container = button.firstElementChild as HTMLElement;
        const textNodes = Array.from(container.childNodes).filter((node) => node.nodeType === Node.TEXT_NODE);
        assert.equal(textNodes.length, 1, `${platform}: command is one real text node, not an image or pseudo-element`);
        assert.ok(textNodes[0].textContent?.trim());
        assert.equal(window.getComputedStyle(container).userSelect, "text", `${platform}: command text is selectable`);
        const prompt = container.querySelector('[aria-hidden="true"]') as HTMLElement;
        assert.equal(window.getComputedStyle(prompt).userSelect, "none", `${platform}: prompt is not part of a selection`);
      }
    }
  } finally {
    cleanup();
    style.remove();
  }
});
