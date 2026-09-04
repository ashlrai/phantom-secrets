const GUIDES = [
  {
    title: "Start with one project",
    body: "Install a pinned public release, verify its receipt, protect one project, inspect the boundary, and launch a supported client.",
    href: "/docs/getting-started",
    action: "Open the quickstart",
  },
  {
    title: "Connect your coding agent",
    body: "Exact setup paths for Claude Code, Cursor, Windsurf, and Codex, including the files each command writes.",
    href: "/docs#connect-an-agent",
    action: "Choose an agent guide",
  },
  {
    title: "Audit the security model",
    body: "Read the trust boundary, attacker assumptions, residual risks, disclosure path, and release evidence.",
    href: "https://github.com/ashlrai/phantom-secrets/blob/main/SECURITY.md",
    action: "Review security",
  },
  {
    title: "Adopt with a team",
    body: "Evaluate local workflows first, define acceptance evidence, and keep hosted commissioning separate.",
    href: "/docs/enterprise-adoption",
    action: "Plan an evaluation",
  },
] as const;

export function DocumentationGateway() {
  return (
    <section className="docs-gateway" aria-labelledby="docs-gateway-title">
      <div className="landing-frame">
        <div className="docs-gateway__intro">
          <div className="landing-section-heading">
            <p className="landing-kicker">Built for humans and coding agents</p>
            <h2 id="docs-gateway-title">Documentation with an evidence trail.</h2>
          </div>
          <p>
            Start with the supported path, then inspect the source, threat model,
            platform matrix, and release receipts. Machine-readable summaries at
            <a href="/llms.txt"> llms.txt</a> and <a href="/llms-full.txt">llms-full.txt</a>
            help coding agents retrieve the same boundaries.
          </p>
        </div>

        <div className="docs-gateway__grid">
          {GUIDES.map((guide) => (
            <article key={guide.title}>
              <h3>{guide.title}</h3>
              <p>{guide.body}</p>
              <a href={guide.href}>{guide.action}</a>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
