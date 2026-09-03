const SURFACES = [
  {
    name: "Protect",
    command: "phantom init",
    outcome:
      "Moves detected values into the selected local vault, then atomically rewrites managed dotenv entries as phm_ placeholders.",
  },
  {
    name: "Delegate",
    command: "phantom exec -- <agent>",
    outcome:
      "Launches a child with fresh session placeholders, a separate proxy bearer, and supported SDK base-URL overrides.",
  },
  {
    name: "Connect",
    command: "phantom setup --client <name>",
    outcome:
      "Writes local MCP configuration for Claude Code, Cursor, Windsurf, or Codex and fails closed when no local runtime is available.",
  },
  {
    name: "Inspect",
    command: "phantom check --staged",
    outcome:
      "Checks staged dotenv content and added lines in other staged files for a bounded set of credential prefixes.",
  },
  {
    name: "Explain",
    command: "phantom agent report --json",
    outcome:
      "Reports value-blind readiness evidence for the current project without turning that report into execution authority.",
  },
  {
    name: "Audit",
    command: "phantom audit verify",
    outcome:
      "Verifies the local HMAC chain and checkpoint against the machine-local audit state; it is not an external attestation.",
  },
] as const;

export function Features() {
  return (
    <section id="features" className="operator-section">
      <div className="landing-frame">
        <div className="landing-section-heading operator-section__heading">
          <p className="landing-kicker">Operator surface</p>
          <h2>Small commands. Explicit effects.</h2>
          <p>
            The CLI, local proxy, vault, and MCP server are open source. Each
            surface reports what it can do and keeps consequential actions
            behind their own confirmation or trusted-terminal boundary.
          </p>
        </div>

        <div className="operator-index">
          {SURFACES.map((surface) => (
            <article key={surface.name}>
              <span>{surface.name}</span>
              <code>{surface.command}</code>
              <p>{surface.outcome}</p>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
