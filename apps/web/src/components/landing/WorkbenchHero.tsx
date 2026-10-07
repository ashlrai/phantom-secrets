import Image from "next/image";

const resourceTypes = [
  { name: "Subscriptions", detail: "Through signed-in CLIs" },
  { name: "API credits", detail: "Separately metered usage" },
  { name: "Local models", detail: "Your configured runtime" },
] as const;

export function WorkbenchHero() {
  return (
    <header className="phantom-workbench" aria-labelledby="workbench-title">
      <div className="phantom-workbench__intro">
        <p className="phantom-workbench__brand">Phantom <span>by AshlrAI</span></p>
        <h1 id="workbench-title">One place for your engineering agents.</h1>
        <p className="phantom-workbench__description">
          Work alongside your agents, or give the fleet an outcome to work toward.
          Bring your signed-in coding tools, separately billed APIs and local models
          into one workbench for chats, projects, traces and review.
        </p>
        <div className="phantom-workbench__actions">
          <a className="phantom-workbench__primary" href="https://verse.ashlr.ai">
            Explore the workbench
          </a>
          <a className="phantom-workbench__secondary" href="#phantom-secrets">
            Protect credentials with Phantom Secrets
          </a>
        </div>
        <p className="phantom-workbench__note">
          The workbench is distributed as <code>@ashlr/hub</code> with the <code>ashlr</code> CLI.
          Your installed tools, account setup and permissions determine what can run.
        </p>
      </div>

      <div className="phantom-workbench__diagram" aria-label="Illustrated engineering workflow, not live account status">
        <ul className="phantom-workbench__resources" aria-label="Distinct resource types">
          {resourceTypes.map(({ name, detail }) => (
            <li key={name}><strong>{name}</strong><span>{detail}</span></li>
          ))}
        </ul>
        <div className="phantom-workbench__center">
          <Image src="/favicon.svg" alt="" width={52} height={52} />
          <strong>Phantom</strong>
          <span>Coordinate the work</span>
        </div>
        <div className="phantom-workbench__modes">
          <section><h2>Work with me</h2><p>Converse, guide and inspect a session.</p></section>
          <section><h2>Work for me</h2><p>Steer outcomes and follow fleet progress.</p></section>
        </div>
        <p className="phantom-workbench__loop">Plan <span aria-hidden="true">›</span> Build <span aria-hidden="true">›</span> Verify <span aria-hidden="true">›</span> Review</p>
        <p className="phantom-workbench__tools">MCP and CLI tools require configuration.</p>
      </div>

      <div className="phantom-workbench__ecosystem" aria-label="Phantom ecosystem projects">
        <a href="#phantom-secrets"><strong>Phantom Secrets</strong><span>Local credential boundary</span></a>
        <a href="https://github.com/ashlrai/locus"><strong>Locus</strong><span>Account and tenant identity</span></a>
        <a href="https://verse.ashlr.ai/ecosystem"><strong>The ecosystem</strong><span>Explore the connected projects</span></a>
      </div>
    </header>
  );
}
