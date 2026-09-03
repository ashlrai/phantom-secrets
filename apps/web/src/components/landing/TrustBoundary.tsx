const PASSES = [
  "Method, path, bounded body, and ordinary request data",
  "A fresh proxy bearer held by the launched child process",
  "The configured route's fixed authentication header, after admission",
];

const STAYS = [
  "Provider credential values in the managed agent context",
  "Client authority to choose which secret or auth header is injected",
  "Placeholder substitution in request headers or bodies",
];

export function TrustBoundary() {
  return (
    <section id="how" className="boundary-section">
      <div className="landing-frame">
        <div className="landing-section-heading boundary-section__heading">
          <p className="landing-kicker">The trust boundary</p>
          <h2>A narrow passage, not ambient secret access.</h2>
          <p>
            Phantom addresses one specific risk: credentialed HTTP work in
            supported agent workflows. Files, unmanaged processes, user
            permissions, and unsupported protocols remain outside this boundary.
          </p>
        </div>

        <div className="boundary-map">
          <div className="boundary-map__side boundary-map__side--agent">
            <span className="boundary-map__label">Agent context</span>
            <strong>Intent and placeholder</strong>
            <code>Authorization: phm_a8f2…</code>
            <code>POST /v1/responses</code>
          </div>

          <div className="boundary-map__seal" aria-label="Authenticated loopback boundary">
            <span>127.0.0.1</span>
            <strong>route gate</strong>
            <small>deny by default</small>
          </div>

          <div className="boundary-map__side boundary-map__side--vault">
            <span className="boundary-map__label">Credential plane</span>
            <strong>Vault and fixed mapping</strong>
            <code>secret: OPENAI_API_KEY</code>
            <code>header: Authorization</code>
          </div>
        </div>

        <div className="boundary-ledger">
          <div>
            <h3>What may cross</h3>
            <ul>
              {PASSES.map((item) => (
                <li key={item}>
                  <span aria-hidden="true">+</span>
                  {item}
                </li>
              ))}
            </ul>
          </div>
          <div>
            <h3>What does not cross</h3>
            <ul>
              {STAYS.map((item) => (
                <li key={item}>
                  <span aria-hidden="true">×</span>
                  {item}
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </section>
  );
}
