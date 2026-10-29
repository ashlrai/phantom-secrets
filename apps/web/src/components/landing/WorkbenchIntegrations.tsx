import Link from "next/link";
import { KEY_ENTRIES } from "./BrandLogos";

const toolNames = new Set(["GitHub", "Vercel", "Cloudflare", "Supabase", "Stripe", "Slack", "Discord", "Sentry", "PostHog", "Docker", "Notion", "Linear", "Figma"]);
const tools = KEY_ENTRIES.filter(({ name }) => toolNames.has(name));

const agents = [
  { name: "Claude Code", next: "Install Claude Code and sign in through its vendor CLI on this machine." },
  { name: "Codex", next: "Install Codex and sign in through its vendor CLI on this machine." },
  { name: "Grok", next: "Install Grok and sign in through its vendor CLI on this machine." },
  { name: "API or local model", next: "Configure an API engine or a local model runtime in Resources. API usage is billed separately; local models need tool support and available serving capacity." },
] as const;

export function WorkbenchIntegrations() {
  return <>
    <section id="connect-agent" className="phantom-integration-band" aria-labelledby="connect-agent-title" style={{ scrollMarginTop: "6rem", minWidth: 0 }}>
      <h2 id="connect-agent-title">Choose your first agent.</h2>
      <p>Expand a choice for the path to your first local session. These instructions do not connect an account or install software.</p>
      <p>First, <Link href="/docs/workbench-setup" className="phantom-workbench__secondary">install and set up Phantom</Link> on your machine. Then follow your agent’s steps below.</p>
      <div style={{ display: "grid", gap: "1rem", minWidth: 0 }}>
        {agents.map(({ name, next }) => <details key={name} style={{ border: "1px solid #252532", borderRadius: "10px", padding: "1rem", overflowWrap: "anywhere", minWidth: 0 }}>
          <summary style={{ cursor: "pointer", padding: ".5rem", color: "#ededf2" }}>{name} — connection steps</summary>
          <ol style={{ paddingInlineStart: "1.5rem", color: "#a8a8b2", lineHeight: 1.7 }}>
            <li>{next} Keep passwords, credentials and private tokens out of chat.</li>
            <li>From a project you authorize Phantom to access, run <code>phm verse</code>. Open the local URL printed by that process; startup may refresh configured accounts.</li>
            <li>Open <strong>Resources</strong> and check that your chosen account or model is ready and its status is fresh. A saved profile alone does not prove a usable connection.</li>
            <li>Choose <strong>Work with me</strong>, create a chat and select a scratch repository. Use <strong>Advanced</strong> to choose your ready account or model, then ask for a small, checkable change. Review the diff and checks before accepting it.</li>
          </ol>
          <Link href="/docs/workbench-setup#connect-a-usable-resource" className="phantom-workbench__secondary">Continue with {name} setup</Link>
        </details>)}
      </div>
      <p>Need help? <Link href="/docs/workbench-troubleshooting" className="phantom-workbench__secondary">Troubleshoot local setup</Link>. Starting a local session does not activate unattended fleet work.</p>
    </section>
    <section className="phantom-integration-band" aria-labelledby="workbench-tools-title">
    <h2 id="workbench-tools-title">Your engineering tools, in the same conversation.</h2>
    <p>Bring configured MCP servers and CLIs for source control, deployment, databases, design and observability. The workbench coordinates tool access; each server, account and permission determines the actions available.</p>
    <ul aria-label="Illustrative tool identities">
      {tools.map(({ name, Logo }) => <li key={name}><Logo aria-hidden="true" /><span>{name}</span></li>)}
    </ul>
    <p>Logos identify products, not endorsement or automatic connection. Subscription CLI sessions, API credentials, MCP tools and local-model runtimes remain separate resources.</p>
    <a href="https://verse.ashlr.ai/ecosystem" className="phantom-workbench__secondary">Explore the engineering toolkit</a>
    </section>
  </>;
}
