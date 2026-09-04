import { Github } from "./Icons";

export function CTA() {
  return (
    <section className="closing-section">
      <div className="landing-frame closing-section__layout">
        <div>
          <p className="landing-kicker">Start locally</p>
          <h2>Run supported API work through the local credential boundary.</h2>
        </div>
        <div className="closing-section__actions">
          <a className="sealed-button sealed-button--primary" href="#install">
            Follow the install path
          </a>
          <a
            className="sealed-button sealed-button--quiet"
            href="https://github.com/ashlrai/phantom-secrets"
          >
            <Github aria-hidden="true" />
            Star or fork on GitHub
          </a>
        </div>
        <p>
          MIT licensed · Local-first open core · Commercial evaluations by
          written agreement
        </p>
      </div>
    </section>
  );
}
