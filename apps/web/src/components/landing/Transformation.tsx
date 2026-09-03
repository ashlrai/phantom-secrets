import {
  ClaudeLogo,
  GitHubLogo,
  OpenAILogo,
  StripeLogo,
} from "./BrandLogos";

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
          <div key={row.name}>
            <row.Logo aria-hidden="true" />
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
          <div className="transformation-grid__passage" aria-hidden="true">
            <span>phantom init</span>
            <b>→</b>
          </div>
          <EnvPanel managed />
        </div>
      </div>
    </section>
  );
}
