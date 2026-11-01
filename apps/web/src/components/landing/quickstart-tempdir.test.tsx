import assert from "node:assert/strict";
import test from "node:test";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { QuickStart } from "./QuickStart";

for (const platform of ["macOS", "Linux"]) {
  test(`${platform} displays a unique TMPDIR staging template`, () => {
    render(<QuickStart />);
    try {
      const selector = screen.getByRole("group", { name: "Choose an operating system" });
      fireEvent.click(within(selector).getByRole("button", { name: platform }));
      const card = screen.getByRole("heading", { level: 3, name: platform }).closest("article");
      assert.ok(card);
      const copy = within(card).getByRole("button", { name: /^Copy command:/ });
      const displayed = Array.from(copy.firstElementChild!.childNodes)
        .filter((node) => node.nodeType === Node.TEXT_NODE)
        .map((node) => node.textContent)
        .join("");

      // Each invocation gets its own directory; quotes preserve TMPDIR containing spaces.
      const stagingLines = displayed.split("\n").filter((line) => /\bmktemp\b/.test(line));
      assert.deepEqual(stagingLines, [
        'phantom_stage="$(mktemp -d "${TMPDIR:-/tmp}/phantom-install.XXXXXX")"',
      ]);
    } finally {
      cleanup();
    }
  });
}

test("every displayed installer stages under a temporary directory and cleans up", () => {
  render(<QuickStart />);
  try {
    const selector = screen.getByRole("group", { name: "Choose an operating system" });
    for (const platform of ["macOS", "Windows", "Linux"]) {
      fireEvent.click(within(selector).getByRole("button", { name: platform }));
      const card = screen.getByRole("heading", { level: 3, name: platform }).closest("article");
      assert.ok(card);
      const copy = within(card).getByRole("button", { name: /^Copy command:/ });
      const displayed = Array.from(copy.firstElementChild!.childNodes)
        .filter((node) => node.nodeType === Node.TEXT_NODE)
        .map((node) => node.textContent)
        .join("");

      if (platform === "Windows") {
        assert.match(displayed, /\$Installer = Join-Path \$env:TEMP \('phantom-install-[^\n]+\[Guid\]::NewGuid\(\)/);
        assert.match(displayed, /Invoke-WebRequest [^\n]+-OutFile \$Installer/);
        assert.match(displayed, /try \{[\s\S]*Invoke-WebRequest[\s\S]*\} finally \{\s*Remove-Item -LiteralPath \$Installer -Force -ErrorAction SilentlyContinue\s*\}/);
      } else {
        assert.ok(displayed.includes('phantom_stage="$(mktemp -d "${TMPDIR:-/tmp}/phantom-install.XXXXXX")"'), platform);
        assert.ok(displayed.includes('phantom_installer="$phantom_stage/install.sh"'), platform);
        assert.match(displayed, /curl [^\n]+--output "\$phantom_installer"/);
        const cleanup = displayed.indexOf(`trap 'rm -f -- "$phantom_installer"; rmdir -- "$phantom_stage" 2>/dev/null || true' EXIT`);
        assert.ok(cleanup >= 0 && cleanup < displayed.indexOf("curl "), `${platform}: install cleanup before download`);
      }
    }
  } finally {
    cleanup();
  }
});
