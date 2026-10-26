const ROUTE_CHECKS = [
  "Fresh proxy bearer authenticates this local session",
  "Built-in service prefix selects the configured HTTPS host",
  "Client control of the route auth header is discarded",
  "Route-owned credential is injected only into that fixed header",
] as const;

const RECEIPT_ROWS = [
  ["response", "identity bytes inspected"],
  ["location", "body"],
  ["pattern", "vault-secret"],
  ["matches", "1"],
] as const;

export function RequestTrace() {
  return (
    <section
      className="request-proof-section"
      aria-labelledby="request-proof-title"
    >
      <div className="landing-frame">
        <div className="request-proof-section__heading">
          <h2 id="request-proof-title">
            Follow one request without following the key.
          </h2>
          <p>
            This synthetic OpenAI trace shows the active local proxy boundary.
            It is an explanatory example, not a live event or an externally
            trusted attestation.
          </p>
        </div>

        <figure className="request-trace">
          <figcaption className="sr-only">
            A value-blind agent request passes through an authenticated,
            configured route and returns only after response credential
            material is inspected and redacted when detected.
          </figcaption>

          <ol
            className="request-trace__flow"
            aria-label="Illustrative proxy request lifecycle"
          >
            <li className="request-trace__request">
              <header>
                <span className="request-trace__number" aria-hidden="true">
                  1
                </span>
                <div>
                  <h3>Agent sends intent</h3>
                  <p>Provider value absent</p>
                </div>
              </header>
              <code className="request-trace__request-line">
                POST /openai/_phantom/[session]/v1/responses
              </code>
              <dl className="request-trace__facts">
                <div>
                  <dt>Fresh session placeholder</dt>
                  <dd>
                    <code>OPENAI_API_KEY=phm_a8f2…</code>
                  </dd>
                </div>
                <div>
                  <dt>Request body</dt>
                  <dd>Bounded, then forwarded byte-for-byte</dd>
                </div>
                <div>
                  <dt>Placeholder handling</dt>
                  <dd>Never resolved from client headers or body</dd>
                </div>
              </dl>
            </li>

            <li className="request-trace__gate">
              <span className="request-trace__number" aria-hidden="true">
                2
              </span>
              <div className="request-trace__gate-copy">
                <p>Authenticated loopback</p>
                <h3>Bounded route</h3>
                <code>127.0.0.1 → TLS upstream</code>
              </div>
              <ul>
                {ROUTE_CHECKS.map((check) => (
                  <li key={check}>
                    <span aria-hidden="true">✓</span>
                    {check}
                  </li>
                ))}
              </ul>
            </li>

            <li className="request-trace__receipt">
              <header>
                <span className="request-trace__number" aria-hidden="true">
                  3
                </span>
                <div>
                  <h3>Agent receives scrubbed bytes</h3>
                  <p>Leak intercepted in this example</p>
                </div>
              </header>
              <pre aria-label="Synthetic scrubbed response">
                <code>{`{
  "id": "resp_example",
  "debug": "[REDACTED:vault-secret]"
}`}</code>
              </pre>
              <dl className="request-trace__receipt-rows">
                {RECEIPT_ROWS.map(([term, detail]) => (
                  <div key={term}>
                    <dt>{term}</dt>
                    <dd>{detail}</dd>
                  </div>
                ))}
              </dl>
              <p className="request-trace__value-note">
                No credential value is shown in this synthetic trace.
              </p>
            </li>
          </ol>

          <p className="request-trace__denial">
            <span aria-hidden="true">×</span>
            Invalid bearers, unknown service definitions, missing route
            credentials, oversized request bodies, and encoded upstream
            responses fail before normal forwarding.
          </p>
        </figure>
      </div>
    </section>
  );
}
