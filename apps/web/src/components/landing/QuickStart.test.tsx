import assert from "node:assert/strict";
import test from "node:test";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { QuickStart } from "./QuickStart";

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
