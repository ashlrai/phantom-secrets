import { KEY_ENTRIES } from "./BrandLogos";

const toolNames = new Set(["GitHub", "Vercel", "Cloudflare", "Supabase", "Stripe", "Slack", "Discord", "Sentry", "PostHog", "Docker", "Notion", "Linear", "Figma"]);
const tools = KEY_ENTRIES.filter(({ name }) => toolNames.has(name));

export function WorkbenchIntegrations() {
  return <section className="phantom-integration-band" aria-labelledby="workbench-tools-title">
    <h2 id="workbench-tools-title">Your engineering tools, in the same conversation.</h2>
    <p>Bring configured MCP servers and CLIs for source control, deployment, databases, design and observability. The workbench coordinates tool access; each server, account and permission determines the actions available.</p>
    <ul aria-label="Illustrative tool identities">
      {tools.map(({ name, Logo }) => <li key={name}><Logo aria-hidden="true" /><span>{name}</span></li>)}
    </ul>
    <p>Logos identify products, not endorsement or automatic connection. Subscription CLI sessions, API credentials, MCP tools and local-model runtimes remain separate resources.</p>
    <a href="https://verse.ashlr.ai/ecosystem" className="phantom-workbench__secondary">Explore the engineering toolkit</a>
  </section>;
}
