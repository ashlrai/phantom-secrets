import Link from "next/link";
import { FaApple, FaLinux, FaWindows } from "react-icons/fa6";
import { CopyButton } from "./CopyButton";
import {
  PUBLIC_RELEASE_RECEIPT,
  PUBLIC_RELEASE_SOURCE_COMMIT,
  PUBLIC_RELEASE_TAG,
  PUBLIC_RELEASE_UNIX_INSTALLER_SHA256,
  PUBLIC_RELEASE_WINDOWS_INSTALLER_SHA256,
} from "@/lib/public-release";

const STEPS = [
  {
    step: `Verify both ${PUBLIC_RELEASE_TAG} binaries`,
    body: "After the platform-specific install, confirm that the CLI and MCP server report the pinned public version.",
    command: "phantom --version\nphantom-mcp --version",
    receipt: PUBLIC_RELEASE_RECEIPT,
  },
  {
    step: "Protect one supported project",
    body: "From an owned Git repository, keep an independent provider recovery copy and begin with a supported HTTP API key—not a database connection string.",
    command: "phantom init",
    receipt: "vault write completed\nmanaged dotenv rewritten\nno plaintext project backup",
  },
] as const;

const RELEASE_ASSET_BASE =
  `https://github.com/ashlrai/phantom-secrets/releases/download/${PUBLIC_RELEASE_TAG}`;

const RAW_SOURCE_BASE =
  `https://raw.githubusercontent.com/ashlrai/phantom-secrets/${PUBLIC_RELEASE_SOURCE_COMMIT}/scripts`;

const PLATFORMS = [
  {
    name: "macOS",
    Icon: FaApple,
    vault: "Keychain when available",
    detail: "Uses Keychain when available. The verified source installer auto-detects Apple Silicon or Intel.",
    source: `${RAW_SOURCE_BASE}/install.sh`,
    command: [
      `(`,
      `set -euo pipefail`,
      `umask 077`,
      `phantom_stage="$(mktemp -d "\${TMPDIR:-/tmp}/phantom-install.XXXXXX")"`,
      `phantom_installer="$phantom_stage/install.sh"`,
      `trap 'rm -f -- "$phantom_installer"; rmdir -- "$phantom_stage" 2>/dev/null || true' EXIT`,
      `curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 --output "$phantom_installer" ${RAW_SOURCE_BASE}/install.sh`,
      `printf '%s  %s\\n' ${PUBLIC_RELEASE_UNIX_INSTALLER_SHA256} "$phantom_installer" | shasum -a 256 -c -`,
      `bash "$phantom_installer"`,
      `"$HOME/.phantom-secrets/bin/phantom" --version`,
      `"$HOME/.phantom-secrets/bin/phantom-mcp" --version`,
      `)`,
    ].join("\n"),
    commandLabel: "Download, verify, install, and check both binaries",
    caveat: "The release is not notarized. Inspect the pinned script and verify its checksum before any policy-dependent unblock.",
    targets: [
      { label: "Apple Silicon", filename: "phantom-aarch64-apple-darwin.tar.gz" },
      { label: "Intel", filename: "phantom-x86_64-apple-darwin.tar.gz" },
    ],
  },
  {
    name: "Windows",
    Icon: FaWindows,
    vault: "Credential Manager when available",
    detail: "Uses current-user Credential Manager when available. PowerShell selects ARM64 or x64.",
    source: `${RAW_SOURCE_BASE}/install.ps1`,
    prompt: "PS>",
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
    commandLabel: "Download, verify, install, and check both binaries",
    caveat: "Windows archives are not Authenticode-signed. Unblock only after checksum verification and only when local policy permits it.",
    targets: [
      { label: "ARM64", filename: "phantom-aarch64-pc-windows-msvc.zip" },
      { label: "x64", filename: "phantom-x86_64-pc-windows-msvc.zip" },
    ],
  },
  {
    name: "Linux",
    Icon: FaLinux,
    vault: "Keyutils initially",
    detail: "Published GNU targets enforce a glibc 2.35 symbol ceiling; musl and Alpine are not published.",
    source: `${RAW_SOURCE_BASE}/install.sh`,
    command: [
      `(`,
      `set -euo pipefail`,
      `umask 077`,
      `phantom_stage="$(mktemp -d "\${TMPDIR:-/tmp}/phantom-install.XXXXXX")"`,
      `phantom_installer="$phantom_stage/install.sh"`,
      `trap 'rm -f -- "$phantom_installer"; rmdir -- "$phantom_stage" 2>/dev/null || true' EXIT`,
      `curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 --output "$phantom_installer" ${RAW_SOURCE_BASE}/install.sh`,
      `printf '%s  %s\\n' ${PUBLIC_RELEASE_UNIX_INSTALLER_SHA256} "$phantom_installer" | sha256sum -c -`,
      `bash "$phantom_installer"`,
      `"$HOME/.phantom-secrets/bin/phantom" --version`,
      `"$HOME/.phantom-secrets/bin/phantom-mcp" --version`,
      `)`,
    ].join("\n"),
    commandLabel: "Download, verify, install, and check both binaries",
    caveat: "The default keyutils vault is session-persistent, not reboot-persistent. Desktop users can migrate to Secret Service; headless environments need a managed passphrase for the encrypted-file backend.",
    targets: [
      { label: "ARM64", filename: "phantom-aarch64-unknown-linux-gnu.tar.gz" },
      { label: "x64", filename: "phantom-x86_64-unknown-linux-gnu.tar.gz" },
    ],
  },
] as const;

export function QuickStart() {
  return (
    <section id="install" className="passage-section" aria-labelledby="passage-title">
      <div className="landing-frame">
        <div className="landing-section-heading">
          <p className="landing-kicker">First passage</p>
          <h2 id="passage-title">Install on your OS. Then protect one project.</h2>
          <p>
            The output below is illustrative output. Ports, routes, vault
            backends, and local findings vary by machine and configuration.
            Direct downloads use the exact {PUBLIC_RELEASE_TAG} GitHub release assets linked
            in the repository.
          </p>
        </div>

        <div className="platform-install-grid" aria-label="Release downloads by operating system">
          {PLATFORMS.map((platform) => (
            <article key={platform.name} className="platform-install-card">
              <div className="platform-install-card__heading">
                <div className="platform-install-card__identity">
                  <platform.Icon aria-hidden="true" />
                  <h3>{platform.name}</h3>
                </div>
                <span>{platform.vault}</span>
              </div>
              <p>{platform.detail}</p>
              <div className="platform-install-card__targets">
                {platform.targets.map(({ label, filename }) => (
                  <div key={filename} className="platform-install-card__target">
                    <a
                      href={`${RELEASE_ASSET_BASE}/${filename}`}
                      aria-label={`Download Phantom ${PUBLIC_RELEASE_TAG} for ${platform.name} ${label}`}
                    >
                      <span>{label}</span>
                      <small>archive {PUBLIC_RELEASE_TAG}</small>
                    </a>
                    <a
                      href={`${RELEASE_ASSET_BASE}/${filename}.sha256`}
                      aria-label={`Download the SHA-256 checksum for Phantom ${PUBLIC_RELEASE_TAG} on ${platform.name} ${label}`}
                    >
                      <small>SHA-256 sidecar</small>
                    </a>
                  </div>
                ))}
              </div>
              <div className="platform-install-card__command">
                <strong>{platform.commandLabel}</strong>
                <a href={platform.source} className="platform-install-card__source">
                  View exact installer source
                </a>
                <CopyButton text={platform.command} prompt={"prompt" in platform ? platform.prompt : "$"} />
              </div>
              <p className="platform-install-card__caveat">{platform.caveat}</p>
            </article>
          ))}
        </div>

        <p className="platform-install-note">
          Every archive is produced by the release workflow with native smoke tests,
          an SPDX SBOM, and a published SHA-256 manifest. That evidence covers the
          release artifact—not every local shell, policy, or credential-store state.
          The command panels download the installer source from the exact {PUBLIC_RELEASE_TAG}
          source commit, verify the fixed script digest, and only then execute the
          local file. The scripts verify the selected archive&apos;s adjacent checksum,
          exact two-binary shape, and versions before promoting it into a user-owned
          install directory. The Linux encrypted-file path needs its managed
          passphrase configured before <code>phantom init</code>; keep that
          passphrase out of agent process inheritance. Review the full{" "}
          <Link href="/docs/getting-started#exact-github-assets-macos-linux-and-windows">
            platform installation guide
          </Link>{" "}and the pinned script before running it. The retired
          <code> phm.dev/install.* </code>endpoints remain non-executable until a
          matching public release is independently accepted.
        </p>

        <ol className="passage-steps">
          {STEPS.map((item, index) => (
            <li key={item.step}>
              <div className="passage-steps__number" aria-hidden="true">
                {String(index + 1).padStart(2, "0")}
              </div>
              <div className="passage-steps__instruction">
                <h3>{item.step}</h3>
                <p>{item.body}</p>
                <CopyButton text={item.command} />
              </div>
              <div className="passage-steps__receipt">
                <span>illustrative receipt</span>
                <pre>{item.receipt}</pre>
              </div>
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}
