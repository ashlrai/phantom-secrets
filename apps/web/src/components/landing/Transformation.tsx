import {
  ClaudeLogo,
  GitHubLogo,
  OpenAILogo,
  StripeLogo,
} from "./BrandLogos";
import { CodexClientLogo } from "./ClientLogos";

const EXAMPLE_ROWS = [
  {
    Logo: OpenAILogo,
    name: "OPENAI_API_KEY",
    before: "example-redacted-openai-value",
    after: "phm_a8f2c4d9e1b7",
  },
  {
    Logo: ClaudeLogo,
    name: "ANTHROPIC_API_KEY",
    before: "example-redacted-anthropic-value",
    after: "phm_2ccb5a91f604",
  },
  {
    Logo: StripeLogo,
    name: "STRIPE_SECRET_KEY",
    before: "example-redacted-stripe-value",
    after: "phm_491e6dc8a273",
  },
  {
    Logo: GitHubLogo,
    name: "GITHUB_TOKEN",
    before: "example-redacted-github-value",
    after: "phm_99a8d2bf17e0",
  },
] as const;

function EnvPanel({ managed }: { managed: boolean }) {
  return (
    <article className={`env-panel${managed ? " env-panel--managed" : ""}`}>
      <header>
        <span aria-hidden="true" />
        <code>.env</code>
        <strong>{managed ? "After phantom init" : "Before"}</strong>
      </header>
      <div className="env-panel__rows">
        {EXAMPLE_ROWS.map((row) => (
          <div
            key={row.name}
            className={row.name === "GITHUB_TOKEN" ? "env-panel__row--github" : undefined}
          >
            <span className="env-panel__logo"><row.Logo aria-hidden="true" /></span>
            <code>
              <span>{row.name}=</span>
              <b>{managed ? row.after : row.before}</b>
            </code>
          </div>
        ))}
      </div>
      <footer>
        {managed
          ? "Agents and application processes receive managed placeholders."
          : "Synthetic examples of plaintext-shaped project configuration."}
      </footer>
    </article>
  );
}

function BoundaryPanel() {
  return (
    <aside className="transformation-boundary" aria-label="Phantom's local credential boundary">
      <div className="transformation-boundary__signal">
        <span aria-hidden="true" />
        Local credential boundary
      </div>
      <div className="transformation-boundary__mark" aria-hidden="true">phm_</div>
      <p>
        Phantom stores the value locally. The project, agent, and repository work
        with a placeholder instead.
      </p>
      <ul>
        <li>Vault keeps the real value out of the file</li>
        <li>Explicit routes receive credentials at the local proxy</li>
        <li>Unsupported routes fail closed</li>
      </ul>
    </aside>
  );
}

function AgentTrace() {
  return (
    <div className="transformation-demo" aria-label="Synthetic Codex and GitHub workflow demo">
      <article className="transformation-trace">
        <header>
          <span aria-hidden="true">$</span>
          <strong>Current local workflow</strong>
          <small>Synthetic trace</small>
        </header>
        <ol>
          <li>
            <code>phantom init</code>
            <span>Moves detected values into the selected local vault.</span>
          </li>
          <li>
            <code>phantom setup --client codex</code>
            <span>Previews then writes Codex&apos;s local MCP entry.</span>
          </li>
          <li>
            <code>phantom exec -- codex &quot;&lt;your task&gt;&quot;</code>
            <span>Starts the agent through the supervised local session.</span>
          </li>
        </ol>
      </article>

      <article className="transformation-handoff">
        <p>One project, three separate surfaces</p>
        <div className="transformation-handoff__flow">
          <div>
            <span className="transformation-handoff__logo transformation-handoff__logo--codex">
              <CodexClientLogo aria-hidden="true" />
            </span>
            <strong>Codex</strong>
            <small>value-blind tools</small>
          </div>
          <span className="transformation-handoff__connector" aria-hidden="true">→</span>
          <div>
            <span className="transformation-handoff__logo transformation-handoff__logo--phantom">phm_</span>
            <strong>Phantom</strong>
            <small>local boundary</small>
          </div>
          <span className="transformation-handoff__connector" aria-hidden="true">→</span>
          <div>
            <span className="transformation-handoff__logo transformation-handoff__logo--github">
              <GitHubLogo aria-hidden="true" />
            </span>
            <strong>GitHub</strong>
            <small>placeholder diff</small>
          </div>
        </div>
        <p className="transformation-handoff__note">
          Codex sees managed names and status. GitHub can receive a diff with a
          <code>phm_</code> placeholder—not a copied provider credential.
        </p>
      </article>
    </div>
  );
}

export function Transformation() {
  return (
    <section className="transformation-section" aria-labelledby="transformation-title">
      <div className="landing-frame">
        <div className="landing-section-heading transformation-section__heading">
          <p className="landing-kicker">The visible change</p>
          <h2 id="transformation-title">The workflow stays familiar. The values move out.</h2>
          <p>
            One local command stores detected values in the selected vault and
            atomically rewrites managed dotenv entries. These examples are
            synthetic; no provider credential appears in this page or its source.
          </p>
        </div>
        <div className="transformation-grid">
          <EnvPanel managed={false} />
          <BoundaryPanel />
          <EnvPanel managed />
        </div>
        <AgentTrace />
      </div>
    </section>
  );
}
