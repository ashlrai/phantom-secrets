import { CopyButton } from "./CopyButton";
import { Github } from "./Icons";
import { RequestTrace } from "./RequestTrace";

const INSTALL_COMMAND =
  "brew tap ashlrai/phantom && brew trust --formula ashlrai/phantom/phantom && brew install ashlrai/phantom/phantom";

export function Hero() {
  return (
    <header className="sealed-hero">
      <div className="sealed-hero__field" aria-hidden="true" />
      <div className="landing-frame sealed-hero__layout">
        <div className="sealed-hero__copy">
          <p className="landing-kicker">
            Open-source credential passage for agentic engineering
          </p>
          <h1>
            Let agents use APIs.
            <span>Keep provider keys out of their context.</span>
          </h1>
          <p className="sealed-hero__lede">
            Phantom gives supported AI workflows managed placeholders. An
            authenticated local proxy admits only exact configured HTTP routes,
            then injects that route&apos;s vault value into its fixed auth header.
          </p>

          <div className="sealed-hero__actions">
            <a className="sealed-button sealed-button--primary" href="#install">
              Install the open-source CLI
            </a>
            <a
              className="sealed-button sealed-button--quiet"
              href="https://github.com/ashlrai/phantom-secrets"
              aria-label="Star Phantom on GitHub"
            >
              <Github aria-hidden="true" />
              Star Phantom on GitHub
            </a>
          </div>

          <div className="sealed-hero__command">
            <span>macOS · reviewed Homebrew path</span>
            <CopyButton text={INSTALL_COMMAND} />
          </div>

          <dl className="sealed-hero__facts">
            <div>
              <dt>License</dt>
              <dd>MIT</dd>
            </div>
            <div>
              <dt>Runtime</dt>
              <dd>Local Rust proxy</dd>
            </div>
            <div>
              <dt>Clients</dt>
              <dd>Claude · Cursor · Windsurf · Codex</dd>
            </div>
          </dl>
          <p className="sealed-hero__community">
            Useful already? Star the repository so more coding agents and
            developers can find the open-source project.
          </p>
        </div>

        <RequestTrace />
      </div>
    </header>
  );
}
