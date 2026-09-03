const STAGES = [
  {
    name: "Agent process",
    detail: "phm_a8f2… + session bearer",
    state: "value-blind",
  },
  {
    name: "Loopback gate",
    detail: "bearer + exact route verified",
    state: "authenticated",
  },
  {
    name: "Local vault",
    detail: "route-owned value retrieved",
    state: "machine-local",
  },
  {
    name: "TLS upstream",
    detail: "fixed auth header injected",
    state: "forwarded",
  },
] as const;

export function RequestTrace() {
  return (
    <figure className="request-trace" aria-labelledby="request-trace-title">
      <figcaption className="request-trace__header">
        <span id="request-trace-title">Authenticated request trace</span>
        <span className="request-trace__status">
          <span aria-hidden="true" /> exact route matched
        </span>
      </figcaption>

      <div className="request-trace__rail" aria-hidden="true">
        <span className="request-trace__pulse" />
      </div>

      <ol className="request-trace__stages">
        {STAGES.map((stage, index) => (
          <li key={stage.name}>
            <span className="request-trace__index" aria-hidden="true">
              {index + 1}
            </span>
            <span className="request-trace__copy">
              <strong>{stage.name}</strong>
              <span>{stage.detail}</span>
            </span>
            <span className="request-trace__state">{stage.state}</span>
          </li>
        ))}
      </ol>

      <div className="request-trace__denial">
        <span aria-hidden="true">×</span>
        Client-supplied auth overrides and body placeholders remain inert.
      </div>
    </figure>
  );
}
