import Link from "next/link";
import { CopyButton } from "./CopyButton";
import {
  PUBLIC_RELEASE_RECEIPT,
  PUBLIC_RELEASE_TAG,
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

const PLATFORMS = [
  {
    name: "macOS",
    vault: "Keychain",
    detail: "Homebrew or release archives for Apple Silicon and Intel.",
    targets: [
      ["Apple Silicon", "phantom-aarch64-apple-darwin.tar.gz"],
      ["Intel", "phantom-x86_64-apple-darwin.tar.gz"],
    ],
  },
  {
    name: "Windows",
    vault: "Credential Manager",
    detail: "Native MSVC archives for Windows on ARM and x64.",
    targets: [
      ["ARM64", "phantom-aarch64-pc-windows-msvc.zip"],
      ["x64", "phantom-x86_64-pc-windows-msvc.zip"],
    ],
  },
  {
    name: "Linux",
    vault: "Keyutils initially",
    detail: "GNU/glibc 2.35+ archives. The default keyring is session-persistent, not reboot-persistent.",
    targets: [
      ["ARM64", "phantom-aarch64-unknown-linux-gnu.tar.gz"],
      ["x64", "phantom-x86_64-unknown-linux-gnu.tar.gz"],
    ],
  },
] as const;

export function QuickStart() {
  return (
    <section id="install" className="passage-section" aria-labelledby="passage-title">
      <div className="landing-frame">
        <div className="landing-section-heading">
          <p className="landing-kicker">First passage</p>
          <h2 id="passage-title">Protect one project, then prove the boundary.</h2>
          <p>
            The output below is illustrative output. Ports, routes, vault
            backends, and local findings vary by machine and configuration.
            Linux and Windows use the exact {PUBLIC_RELEASE_TAG} GitHub release assets linked
            in the repository.
          </p>
        </div>

        <div className="platform-install-grid" aria-label="Release downloads by operating system">
          {PLATFORMS.map((platform) => (
            <article key={platform.name} className="platform-install-card">
              <div className="platform-install-card__heading">
                <h3>{platform.name}</h3>
                <span>{platform.vault}</span>
              </div>
              <p>{platform.detail}</p>
              <div className="platform-install-card__targets">
                {platform.targets.map(([label, filename]) => (
                  <a
                    key={filename}
                    href={`${RELEASE_ASSET_BASE}/${filename}`}
                    aria-label={`Download Phantom ${PUBLIC_RELEASE_TAG} for ${platform.name} ${label}`}
                  >
                    <span>{label}</span>
                    <small>download {PUBLIC_RELEASE_TAG}</small>
                  </a>
                ))}
              </div>
            </article>
          ))}
        </div>

        <p className="platform-install-note">
          Every archive is produced by the release workflow with native smoke tests,
          an SPDX SBOM, and a published SHA-256 manifest. That evidence covers the
          release artifact—not every local shell, policy, or credential-store state.
          Download the adjacent <code>.sha256</code> sidecar and follow the exact
          verification, extraction, and PATH steps in the{" "}
          <Link href="/docs/getting-started#exact-github-assets-macos-linux-and-windows">
            platform installation guide
          </Link>. Windows archives are not Authenticode-signed; verify the published
          checksum before any explicit unblock. Linux users on the current public
          {PUBLIC_RELEASE_TAG} should use the initial
          non-reboot-persistent keyutils path, or configure the encrypted-file
          backend before <code>phantom init</code> when persistence is required.
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
