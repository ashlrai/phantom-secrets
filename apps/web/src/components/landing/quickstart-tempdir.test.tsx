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
