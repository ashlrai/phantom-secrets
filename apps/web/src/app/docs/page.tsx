import type { Metadata } from "next";
import Link from "next/link";
import { Nav } from "@/components/landing/Nav";
import { SiteFooter } from "@/components/landing/SiteFooter";
import { CopyButton } from "@/components/landing/CopyButton";
import { AskDocumentation } from "@/components/docs/AskDocumentation";
import { WORKBENCH_RELEASE } from "@/lib/workbench-release";
import { PUBLIC_RELEASE_TAG } from "@/lib/public-release";
import { SecretUseCases } from "@/components/landing/SecretUseCases";

export const metadata: Metadata = {
  title: "Documentation",
  description:
    "Install the Phantom workbench, configure agents and bounded autonomy, or protect credentials with Phantom Secrets.",
  alternates: { canonical: "/docs" },
  openGraph: {
    type: "website",
    siteName: "Phantom",
    title: "Phantom Documentation — Workbench and Secrets guides",
    description: "Install the Phantom workbench, configure agents and bounded autonomy, or protect credentials with Phantom Secrets.",
    url: "/docs",
    locale: "en_US",
    images: [{ url: "/og-image.png", width: 1200, height: 630, alt: "Phantom open-source documentation and credential boundary." }],
  },
  twitter: {
    card: "summary_large_image",
    site: "@ashlrai",
    creator: "@ashlrai",
    title: "Phantom Documentation — Workbench and Secrets guides",
    description: "Workbench installation, agent setup, autonomous fleet commissioning and Phantom Secrets documentation.",
    images: ["/og-image.png"],
  },
};

const COLLECTIONS = [
  {
    title: "Use Phantom Secrets",
    id: "use-phantom",
    links: [
      ["Complete getting started guide", "/docs/getting-started"],
      ["Safe delegation quickstart", "/docs/delegation-quickstart"],
      ["Protect API keys from coding agents", "/docs/protect-api-keys-from-ai-coding-agents"],
      ["MCP secrets manager guide", "/docs/mcp-secrets-manager"],
      ["Troubleshooting", "/docs/troubleshooting"],
    ],
  },
  {
    title: "Connect an agent",
    id: "connect-an-agent",
    links: [
      ["Claude Code", "/docs/claude-code"],
      ["Cursor", "/docs/cursor"],
      ["Windsurf", "/docs/windsurf"],
      ["Codex", "/docs/codex"],
    ],
  },
  {
    title: "Evaluate trust",
    id: "evaluate-trust",
    links: [
      ["Security model", "https://github.com/ashlrai/phantom-secrets/blob/main/SECURITY.md"],
      ["Threat model", "https://github.com/ashlrai/phantom-secrets/blob/main/THREAT_MODEL.md"],
      ["Architecture", "/docs/architecture"],
      ["Platform support", "/docs/platform-support"],
    ],
  },
  {
    title: "Adopt and contribute",
    id: "adopt-and-contribute",
    links: [
      ["Enterprise adoption", "/docs/enterprise-adoption"],
      ["Versioned public fact sheet", "/docs/public-fact-sheet"],
      ["Government evaluation", "https://github.com/ashlrai/phantom-secrets/blob/main/docs/government-evaluation.md"],
      ["Contributing", "https://github.com/ashlrai/phantom-secrets/blob/main/CONTRIBUTING.md"],
      ["Project roadmap", "https://github.com/ashlrai/phantom-secrets/blob/main/ROADMAP.md"],
    ],
  },
] as const;

export default function DocsPage() {
  return (
    <>
      <Nav />
      <main id="main-content" tabIndex={-1} className="docs-page">
        <header className="docs-page__hero">
          <div className="landing-frame">
            <p className="landing-kicker">Phantom documentation</p>
            <h1>Put your engineering agents to work.</h1>
            <p>
              Install Phantom, make your first useful turn, and build a fleet with
              clear permissions and measurable outcomes. Protect supported
              credential paths with the separate Phantom Secrets tools.
            </p>
            <div className="docs-page__command">
              <CopyButton text={WORKBENCH_RELEASE?.installCommand ?? "npm install -g @ashlr/phantom"} />
            </div>
            <p className="docs-page__release">
              Workbench {WORKBENCH_RELEASE?.version ?? "release record unavailable"}; Phantom Secrets {PUBLIC_RELEASE_TAG}.
              Installation, account readiness and autonomous activation are separate steps.
            </p>
            <AskDocumentation path="/docs" />
          </div>
        </header>

        <section className="landing-frame docs-workbench" aria-labelledby="workbench-guides-title">
          <div className="docs-workbench__intro">
            <h2 id="workbench-guides-title">Phantom workbench</h2>
            <p>From the first local chat to a fleet you can inspect, steer and stop.</p>
            <Link href="/docs/workbench">Read the overview</Link>
          </div>
          <ol className="docs-workbench__guides">
            <li><Link href="/docs/workbench-setup"><strong>Install and open Phantom</strong><span>CLI, local console, first turn and desktop installation.</span></Link></li>
            <li><Link href="/docs/workbench-agents"><strong>Let an agent help you set up</strong><span>Discovery, machine-readable contracts and operator steps.</span></Link></li>
            <li><Link href="/docs/workbench-autonomy"><strong>Commission a fleet</strong><span>Resources, standing grants, outcomes and improvement evidence.</span></Link></li>
            <li><Link href="/docs/workbench-reference"><strong>Find the right command</strong><span>Installed help, JSON discovery and effect boundaries.</span></Link></li>
            <li><Link href="/docs/workbench-troubleshooting"><strong>Resolve a blocker</strong><span>Installation, accounts, quotas and resident service admission.</span></Link></li>
          </ol>
        </section>
        <SecretUseCases />
        <div className="landing-frame docs-product-heading"><h2>Phantom Secrets</h2><p>Protect API keys in supported coding-agent workflows. The Secrets executable is <code>phantom</code>; the workbench is <code>phm</code>.</p></div>
        <section className="landing-frame docs-page__collections" aria-label="Documentation collections">
          {COLLECTIONS.map((collection) => (
            <article key={collection.title}>
              <h3 id={collection.id}>{collection.title}</h3>
              <ul>
                {collection.links.map(([label, href]) => (
                  <li key={href}>
                    <Link href={href}>{label}</Link>
                  </li>
                ))}
              </ul>
            </article>
          ))}
        </section>

        <section className="docs-page__agents">
          <div className="landing-frame">
            <div>
              <p className="landing-kicker">Machine-readable context</p>
              <h2>Give agents the same guide you use.</h2>
            </div>
            <div>
              <p>
                Fetch the workbench manifest and raw Markdown to discover setup,
                commands and operator-only steps. The Secrets references describe
                the separate credential boundary. Public docs do not report your local readiness.
              </p>
              <div className="docs-page__agent-links">
                <Link href="/docs/manifest.json">Documentation manifest</Link>
                <Link href="/workbench/llms.txt">Workbench llms.txt</Link>
                <Link href="/workbench/llms-full.txt">Full workbench reference</Link>
                <Link href="/llms.txt">Secrets and ecosystem llms.txt</Link>
                <Link href="/llms-full.txt">Read llms-full.txt</Link>
                <a href="https://github.com/ashlrai/phantom-secrets">View the source on GitHub</a>
              </div>
            </div>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
