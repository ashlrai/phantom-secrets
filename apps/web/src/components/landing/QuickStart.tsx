import { CopyButton } from "./CopyButton";
import {
  PUBLIC_RELEASE_RECEIPT,
  PUBLIC_RELEASE_TAG,
} from "@/lib/public-release";

const STEPS = [
  {
    step: `Install ${PUBLIC_RELEASE_TAG} on macOS`,
    body: "Use the reviewed Homebrew tap, trust, and fully qualified formula path.",
    command:
      "brew tap ashlrai/phantom\nbrew trust --formula ashlrai/phantom/phantom\nbrew install ashlrai/phantom/phantom",
    receipt: PUBLIC_RELEASE_RECEIPT,
  },
  {
    step: "Protect and inspect",
    body: "Initialize one project, then inspect its local readiness before launching an agent.",
    command: "phantom init\nphantom agent doctor",
    receipt: "vault accessible\ndotenv managed\nMCP wiring inspected",
  },
  {
    step: "Launch the bounded session",
    body: "Run a supported client through the authenticated loopback proxy.",
    command: "phantom exec -- claude",
    receipt:
      "127.0.0.1:<ephemeral-port>\nconfigured SDK route overrides\nfresh child authorization",
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
    vault: "Kernel keyring",
    detail: "GNU/glibc 2.35+ archives. The default keyring is session-persistent, not reboot-persistent.",
    targets: [
      ["ARM64", "phantom-aarch64-unknown-linux-gnu.tar.gz"],
      ["x64", "phantom-x86_64-unknown-linux-gnu.tar.gz"],
    ],
  },
] as const;

export function QuickStart() {
  return (
    <section className="passage-section" aria-labelledby="passage-title">
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
