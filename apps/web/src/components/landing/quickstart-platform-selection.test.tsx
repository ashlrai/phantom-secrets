import assert from "node:assert/strict";
import test from "node:test";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { QuickStart } from "./QuickStart";
import {
  PUBLIC_RELEASE_SOURCE_COMMIT,
  PUBLIC_RELEASE_TAG,
  PUBLIC_RELEASE_UNIX_INSTALLER_SHA256,
  PUBLIC_RELEASE_WINDOWS_INSTALLER_SHA256,
} from "@/lib/public-release";

const RELEASE_ASSET_BASE =
  `https://github.com/ashlrai/phantom-secrets/releases/download/${PUBLIC_RELEASE_TAG}`;
const RAW_SOURCE_BASE =
  `https://raw.githubusercontent.com/ashlrai/phantom-secrets/${PUBLIC_RELEASE_SOURCE_COMMIT}/scripts`;

const unixInstallCommand = (checksum: string) =>
  [
    `(`,
    `set -euo pipefail`,
    `umask 077`,
    `phantom_stage="$(mktemp -d "\${TMPDIR:-/tmp}/phantom-install.XXXXXX")"`,
    `phantom_installer="$phantom_stage/install.sh"`,
    `trap 'rm -f -- "$phantom_installer"; rmdir -- "$phantom_stage" 2>/dev/null || true' EXIT`,
    `curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 --output "$phantom_installer" ${RAW_SOURCE_BASE}/install.sh`,
    `printf '%s  %s\\n' ${PUBLIC_RELEASE_UNIX_INSTALLER_SHA256} "$phantom_installer" | ${checksum}`,
    `bash "$phantom_installer"`,
    `"$HOME/.phantom-secrets/bin/phantom" --version`,
    `"$HOME/.phantom-secrets/bin/phantom-mcp" --version`,
    `)`,
  ].join("\n");

const EXPECTED = [
  {
    name: "macOS",
    vault: "Keychain when available",
    detail: "Uses Keychain when available. The verified source installer auto-detects Apple Silicon or Intel.",
    prompt: "$",
    source: `${RAW_SOURCE_BASE}/install.sh`,
    command: unixInstallCommand("shasum -a 256 -c -"),
    caveat: "The release is not notarized. Inspect the pinned script and verify its checksum before any policy-dependent unblock.",
    targets: [
      { label: "Apple Silicon", filename: "phantom-aarch64-apple-darwin.tar.gz" },
      { label: "Intel", filename: "phantom-x86_64-apple-darwin.tar.gz" },
    ],
  },
  {
    name: "Windows",
    vault: "Credential Manager when available",
    detail: "Uses current-user Credential Manager when available. PowerShell selects ARM64 or x64.",
    prompt: "PS>",
    source: `${RAW_SOURCE_BASE}/install.ps1`,
    command: [
      `& {`,
      `$ErrorActionPreference = 'Stop'`,
      `$Installer = Join-Path $env:TEMP ('phantom-install-${PUBLIC_RELEASE_TAG}-{0}.ps1' -f [Guid]::NewGuid().ToString('N'))`,
      `try {`,
      `  Invoke-WebRequest -Uri '${RAW_SOURCE_BASE}/install.ps1' -OutFile $Installer`,
      `  $Expected = '${PUBLIC_RELEASE_WINDOWS_INSTALLER_SHA256}'`,
      `  $Actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Installer).Hash.ToLowerInvariant()`,
      `  if ($Actual -ne $Expected) { throw 'Phantom installer checksum mismatch' }`,
      `  & $Installer`,
      `  if (-not $?) { throw 'Phantom installer failed' }`,
      `  & "$env:USERPROFILE\\.phantom-secrets\\bin\\phantom.exe" --version`,
      `  if (-not $?) { throw 'Phantom CLI verification failed' }`,
      `  & "$env:USERPROFILE\\.phantom-secrets\\bin\\phantom-mcp.exe" --version`,
      `  if (-not $?) { throw 'Phantom MCP verification failed' }`,
      `} finally {`,
      `  Remove-Item -LiteralPath $Installer -Force -ErrorAction SilentlyContinue`,
      `}`,
      `}`,
    ].join("\n"),
    caveat: "Windows archives are not Authenticode-signed. Unblock only after checksum verification and only when local policy permits it.",
    targets: [
      { label: "ARM64", filename: "phantom-aarch64-pc-windows-msvc.zip" },
      { label: "x64", filename: "phantom-x86_64-pc-windows-msvc.zip" },
    ],
  },
  {
    name: "Linux",
    vault: "Keyutils initially",
    detail: "Published GNU targets enforce a glibc 2.35 symbol ceiling; musl and Alpine are not published.",
    prompt: "$",
    source: `${RAW_SOURCE_BASE}/install.sh`,
    command: unixInstallCommand("sha256sum -c -"),
    caveat: "The default keyutils vault is session-persistent, not reboot-persistent. Desktop users can migrate to Secret Service; headless environments need a managed passphrase for the encrypted-file backend.",
    targets: [
      { label: "ARM64", filename: "phantom-aarch64-unknown-linux-gnu.tar.gz" },
      { label: "x64", filename: "phantom-x86_64-unknown-linux-gnu.tar.gz" },
    ],
  },
];

// The command is rendered as a text node beside visually hidden labels; join
// the direct text nodes to recover exactly what the page displays. This test
// never evaluates it in a shell.
function displayedCommand(command: HTMLElement) {
  return Array.from(command.firstElementChild!.childNodes)
    .filter((node) => node.nodeType === Node.TEXT_NODE)
    .map((node) => node.textContent)
    .join("");
}

test("selecting each platform displays its corresponding instructions", () => {
  render(<QuickStart />);
  try {
    const region = screen.getByRole("region", { name: "Install on your OS. Then protect one project." });
    const selector = within(region).getByRole("group", { name: "Choose an operating system" });
    const names = EXPECTED.map((platform) => platform.name);

    for (const platform of EXPECTED) {
      const button = within(selector).getByRole("button", { name: platform.name });
      fireEvent.click(button);
      assert.equal(button.getAttribute("aria-pressed"), "true", platform.name);
      for (const other of names.filter((name) => name !== platform.name)) {
        const control = within(selector).getByRole("button", { name: other });
        assert.equal(control.getAttribute("aria-pressed"), "false", `${platform.name}: ${other} stays unselected`);
      }

      const cards = within(region).getAllByRole("article");
      assert.equal(cards.length, 1, `${platform.name}: only the selected platform's card is displayed`);
      const card = cards[0];
      assert.equal(within(card).getByRole("heading", { level: 3 }).textContent, platform.name);
      assert.ok(within(card).getByText(platform.vault));
      assert.ok(within(card).getByText(platform.detail));

      const targets = card.querySelector<HTMLElement>(".platform-install-card__targets");
      assert.ok(targets);
      assert.equal(within(targets).getAllByRole("link").length, platform.targets.length * 2);
      for (const target of platform.targets) {
        const archive: HTMLElement = within(targets).getByRole("link", {
          name: `Download Phantom ${PUBLIC_RELEASE_TAG} for ${platform.name} ${target.label}`,
        });
        assert.equal(archive.getAttribute("href"), `${RELEASE_ASSET_BASE}/${target.filename}`);
        assert.ok(within(archive).getByText(target.label));
        assert.ok(within(archive).getByText(`archive ${PUBLIC_RELEASE_TAG}`));
        const checksum: HTMLElement = within(targets).getByRole("link", {
          name: `Download the SHA-256 checksum for Phantom ${PUBLIC_RELEASE_TAG} on ${platform.name} ${target.label}`,
        });
        assert.equal(checksum.getAttribute("href"), `${RELEASE_ASSET_BASE}/${target.filename}.sha256`);
        assert.ok(within(checksum).getByText("SHA-256 sidecar"));
      }

      const panel = card.querySelector<HTMLElement>(".platform-install-card__command");
      assert.ok(panel);
      assert.ok(within(panel).getByText("Download, verify, install, and check both binaries"));
      const source = within(panel).getByRole("link", { name: "View exact installer source" });
      assert.equal(source.getAttribute("href"), platform.source);
      const command = within(panel).getByRole("button", { name: /^Copy command:/ });
      assert.equal(command.querySelector('[aria-hidden="true"]')?.textContent?.trim(), platform.prompt);
      assert.equal(displayedCommand(command), platform.command, `${platform.name}: displayed install command`);

      const caveat = within(card).getByText(platform.caveat);
      assert.equal(caveat.className, "platform-install-card__caveat");

      // Platform selection never displaces the shared follow-up instructions.
      assert.equal(within(region).getAllByRole("listitem").length, 2, `${platform.name}: numbered steps remain`);
    }
  } finally {
    cleanup();
  }
});

test("macOS instructions display before any selection and stay after re-selection", () => {
  render(<QuickStart />);
  try {
    const selector = screen.getByRole("group", { name: "Choose an operating system" });
    const macos = within(selector).getByRole("button", { name: "macOS" });
    assert.equal(macos.getAttribute("aria-pressed"), "true");
    assert.equal(screen.getAllByRole("article").length, 1);
    assert.ok(screen.getByRole("heading", { level: 3, name: "macOS" }));

    fireEvent.click(macos);
    assert.equal(macos.getAttribute("aria-pressed"), "true");
    assert.equal(screen.getAllByRole("article").length, 1);
    const card = screen.getByRole("heading", { level: 3, name: "macOS" }).closest("article");
    assert.ok(card);
    assert.equal(displayedCommand(within(card).getByRole("button", { name: /^Copy command:/ })), EXPECTED[0].command);
  } finally {
    cleanup();
  }
});
