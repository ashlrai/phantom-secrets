import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { QuickStart } from "./QuickStart";
import {
  PUBLIC_RELEASE_SOURCE_COMMIT,
  PUBLIC_RELEASE_TAG,
  PUBLIC_RELEASE_UNIX_INSTALLER_SHA256,
} from "@/lib/public-release";

const sourceBase =
  `https://raw.githubusercontent.com/ashlrai/phantom-secrets/${PUBLIC_RELEASE_SOURCE_COMMIT}/scripts`;

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

// Every displayed line that expands a staging or install path must keep its
// exact quoted form: on Unix an unquoted expansion would split a TMPDIR or
// HOME containing spaces into extra arguments, and on Windows the quoted
// USERPROFILE invocation is what makes `&` run one literal path. Matching the
// whole line (not just a fragment) also fails if a new unquoted reference is
// added on a line of its own.
const unixStagingLines = (checksum: string) => [
  `phantom_stage="$(mktemp -d "\${TMPDIR:-/tmp}/phantom-install.XXXXXX")"`,
  `phantom_installer="$phantom_stage/install.sh"`,
  `trap 'rm -f -- "$phantom_installer"; rmdir -- "$phantom_stage" 2>/dev/null || true' EXIT`,
  `curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 --output "$phantom_installer" ${sourceBase}/install.sh`,
  `printf '%s  %s\\n' ${PUBLIC_RELEASE_UNIX_INSTALLER_SHA256} "$phantom_installer" | ${checksum}`,
  `bash "$phantom_installer"`,
  `"$HOME/.phantom-secrets/bin/phantom" --version`,
  `"$HOME/.phantom-secrets/bin/phantom-mcp" --version`,
];

for (const [platform, checksum] of [
  ["macOS", "shasum -a 256 -c -"],
  ["Linux", "sha256sum -c -"],
] as const) {
  test(`${platform} keeps every displayed staging-path line quoted`, () => {
    const displayed = displayedCommand(platform);
    const pathLines = displayed
      .split("\n")
      .filter((line) => /[$][{]?(TMPDIR|HOME|phantom_)/.test(line));
    assert.deepEqual(pathLines, unixStagingLines(checksum));
  });
}

test("Windows keeps every displayed staging-path line in its runnable form", () => {
  const displayed = displayedCommand("Windows");
  const pathLines = displayed
    .split("\n")
    .filter((line) => /\$env:(TEMP|USERPROFILE)|\$Installer\b/.test(line));
  assert.deepEqual(pathLines, [
    `$Installer = Join-Path $env:TEMP ('phantom-install-${PUBLIC_RELEASE_TAG}-{0}.ps1' -f [Guid]::NewGuid().ToString('N'))`,
    `  Invoke-WebRequest -Uri '${sourceBase}/install.ps1' -OutFile $Installer`,
    `  $Actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Installer).Hash.ToLowerInvariant()`,
    `  & $Installer`,
    `  & "$env:USERPROFILE\\.phantom-secrets\\bin\\phantom.exe" --version`,
    `  & "$env:USERPROFILE\\.phantom-secrets\\bin\\phantom-mcp.exe" --version`,
    `  Remove-Item -LiteralPath $Installer -Force -ErrorAction SilentlyContinue`,
  ]);
});

// Feed each displayed version-check command word through a real shell parse
// under a HOME whose path contains a space. Only the quoted form expands to a
// single word that resolves to the binary; an unquoted expansion would
// word-split at the space and leave extra arguments.
for (const platform of ["macOS", "Linux"]) {
  test(`${platform} displayed version checks resolve under a space-containing HOME`, (t) => {
    const displayed = displayedCommand(platform);
    const checks = displayed.split("\n").filter((line) => line.includes("$HOME/"));
    assert.deepEqual(checks, [
      `"$HOME/.phantom-secrets/bin/phantom" --version`,
      `"$HOME/.phantom-secrets/bin/phantom-mcp" --version`,
    ]);

    const home = mkdtempSync(path.join(tmpdir(), "phantom home "));
    t.after(() => rmSync(home, { recursive: true, force: true }));
    const bin = path.join(home, ".phantom-secrets", "bin");
    mkdirSync(bin, { recursive: true });
    for (const name of ["phantom", "phantom-mcp"]) writeFileSync(path.join(bin, name), "");

    for (const [index, line] of checks.entries()) {
      const command = line.replace(/ --version$/, "");
      assert.notEqual(command, line, `${platform}: displayed line ends with --version`);
      const result = spawnSync(
        "bash",
        ["-c", 'eval "set -- $COMMAND" && test "$#" -eq 1 && test -f "$1" && printf "%s\\n" "$1"'],
        { env: { ...process.env, HOME: home, COMMAND: command }, encoding: "utf8" },
      );
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout.trim(), path.join(bin, ["phantom", "phantom-mcp"][index]), platform);
    }
  });
}
