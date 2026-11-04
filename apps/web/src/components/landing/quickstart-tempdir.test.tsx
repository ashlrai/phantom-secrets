import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
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

// The component quotes the staging template and every staged path so TMPDIR
// and HOME may contain spaces; the rendered text must keep exactly those
// quotes for the copied command to behave the way it is displayed.
const QUOTED_STAGED_PATHS = {
  unix: [
    '"${TMPDIR:-/tmp}/phantom-install.XXXXXX"',
    '"$phantom_stage/install.sh"',
    '"$phantom_installer"',
    '"$phantom_stage"',
    '"$HOME/.phantom-secrets/bin/phantom"',
    '"$HOME/.phantom-secrets/bin/phantom-mcp"',
  ],
  windows: [
    '"$env:USERPROFILE\\.phantom-secrets\\bin\\phantom.exe"',
    '"$env:USERPROFILE\\.phantom-secrets\\bin\\phantom-mcp.exe"',
  ],
} as const;

test("displayed temporary-directory commands keep every quoted path", () => {
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

      const quoted = platform === "Windows" ? QUOTED_STAGED_PATHS.windows : QUOTED_STAGED_PATHS.unix;
      for (const fragment of quoted) {
        assert.ok(displayed.includes(fragment), `${platform}: displayed command keeps ${fragment}`);
      }
      if (platform !== "Windows") {
        assert.ok(
          displayed.includes('phantom_stage="$(mktemp -d "${TMPDIR:-/tmp}/phantom-install.XXXXXX")"'),
          `${platform}: mktemp template keeps both quote pairs`,
        );
      }
      // Removing each quoted span must leave no staged-path expansion behind:
      // a path outside quotes would split on spaces in TMPDIR or HOME.
      const unquoted = quoted.reduce((text, fragment) => text.split(fragment).join(""), displayed);
      if (platform === "Windows") {
        assert.doesNotMatch(unquoted, /\$env:USERPROFILE/, platform);
      } else {
        assert.doesNotMatch(unquoted, /\$[A-Za-z_{]/, `${platform}: unquoted staged-path expansion`);
      }
    }
  } finally {
    cleanup();
  }
});

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

// Runs the displayed staging prologue (through the EXIT trap) in a real shell
// with TMPDIR unset: the directory must land under /tmp and be gone afterwards.
for (const platform of ["macOS", "Linux"]) {
  test(`${platform} staging command defaults to /tmp when TMPDIR is unset and cleans up`, () => {
    render(<QuickStart />);
    let displayed = "";
    try {
      const selector = screen.getByRole("group", { name: "Choose an operating system" });
      fireEvent.click(within(selector).getByRole("button", { name: platform }));
      const card = screen.getByRole("heading", { level: 3, name: platform }).closest("article");
      assert.ok(card);
      const copy = within(card).getByRole("button", { name: /^Copy command:/ });
      displayed = Array.from(copy.firstElementChild!.childNodes)
        .filter((node) => node.nodeType === Node.TEXT_NODE)
        .map((node) => node.textContent)
        .join("");
    } finally {
      cleanup();
    }

    const lines = displayed.split("\n");
    const trap = lines.findIndex((line) => line.startsWith("trap "));
    assert.ok(trap > 0, `${platform}: displayed command installs an EXIT trap`);
    // Keep "(" ... trap, then create a fixture file and report the directory.
    const script = [
      ...lines.slice(0, trap + 1),
      'printf x > "$phantom_installer"',
      'printf %s "$phantom_stage"',
      ")",
    ].join("\n");

    const env = { ...process.env };
    delete env.TMPDIR;
    const result = spawnSync("sh", ["-c", script], { env, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    const stage = result.stdout;
    assert.match(stage, /^\/tmp\/phantom-install\.[A-Za-z0-9]{6}$/);
    assert.equal(existsSync(stage), false, `${platform}: staging directory removed on exit`);
  });
}
