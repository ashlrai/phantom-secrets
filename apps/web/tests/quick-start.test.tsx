import assert from "node:assert/strict";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { QuickStart } from "../src/components/landing/QuickStart";

// The macOS and Linux cards are the two displayed install variants that use a
// staging-directory variable; the Windows card stages a temporary installer
// file through Join-Path instead, so it has no staged paths to quote.
const STAGED = /\$(?:\{phantom_(?:stage|installer)\}|phantom_(?:stage|installer)\b)/g;

function displayedCommand(platform: string) {
  render(<QuickStart />);
  try {
    const selector = screen.getByRole("group", { name: "Choose an operating system" });
    fireEvent.click(within(selector).getByRole("button", { name: platform }));
    const card = screen.getByRole("heading", { level: 3, name: platform }).closest("article");
    assert.ok(card);
    const copy = within(card).getByRole("button", { name: /^Copy command:/ });
    return Array.from(copy.firstElementChild!.childNodes)
      .filter((node) => node.nodeType === Node.TEXT_NODE)
      .map((node) => node.textContent)
      .join("");
  } finally {
    cleanup();
  }
}

// A staging expansion is safe as a path only inside double quotes: outside
// them a TMPDIR containing spaces would word-split into extra arguments. On a
// displayed line an expansion is quoted exactly when an odd number of
// double-quote characters precede it, and the line must balance its quotes so
// a stray unclosed quote cannot fake the count. Single quotes are transparent
// on purpose: the EXIT trap stores '... "$phantom_installer" ...' verbatim and
// re-parses it on exit, so the inner double quotes are what quote the paths.
function unquotedExpansions(line: string) {
  assert.equal(line.split('"').length % 2, 1, `unbalanced double quotes: ${line}`);
  return [...line.matchAll(STAGED)].filter(
    (match) => line.slice(0, match.index).split('"').length % 2 === 1,
  );
}

for (const platform of ["macOS", "Linux"]) {
  test(`${platform} quotes the staging-directory variable at every displayed path use`, () => {
    const displayed = displayedCommand(platform);
    const lines = displayed.split("\n");
    const stagedLines = lines.filter((line) => line.match(STAGED) !== null);

    // Non-vacuous coverage: the displayed variant must actually use the staging
    // variable as a path when deriving the installer path, downloading into it,
    // executing it, and removing both paths in the EXIT trap.
    for (const fragment of [
      '"$phantom_stage/install.sh"',
      '--output "$phantom_installer"',
      'bash "$phantom_installer"',
      'rmdir -- "$phantom_stage"',
    ]) {
      assert.ok(
        stagedLines.some((line) => line.includes(fragment)),
        `${platform}: displayed command keeps ${fragment}`,
      );
    }

    const offenders = lines.flatMap((line) =>
      unquotedExpansions(line).map((match) => `${line} :: ${match[0]}`),
    );
    assert.deepEqual(
      offenders,
      [],
      `${platform}: every $phantom_stage/$phantom_installer path use stays double-quoted`,
    );
  });
}

for (const platform of ["macOS", "Linux"]) {
  test(`${platform} displayed command keeps TMPDIR quoted and usable with spaces`, () => {
    const displayed = displayedCommand(platform);
    const line = displayed.split("\n").find((l) => l.startsWith("phantom_stage="));
    assert.ok(line, `${platform}: displayed command assigns phantom_stage`);
    assert.ok(
      line.includes('mktemp -d "${TMPDIR:-/tmp}/phantom-install.XXXXXX"'),
      `${platform}: TMPDIR expansion sits inside double quotes`,
    );

    // Run the displayed assignment with a TMPDIR that contains spaces.
    const parent = mkdtempSync(join(tmpdir(), "phantom tmpdir "));
    try {
      const result = spawnSync("bash", ["-c", `set -eu\n${line}\nprintf '%s' "$phantom_stage"`], {
        env: { PATH: process.env.PATH ?? "", TMPDIR: parent },
        encoding: "utf8",
      });
      assert.equal(result.status, 0, result.stderr);
      assert.ok(result.stdout.startsWith(`${parent}/phantom-install.`), result.stdout);
      assert.ok(existsSync(result.stdout));
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  });
}
