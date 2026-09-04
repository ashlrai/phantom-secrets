import type { Metadata } from "next";
import Link from "next/link";
import { Nav } from "@/components/landing/Nav";
import { SiteFooter } from "@/components/landing/SiteFooter";
import { CopyButton } from "@/components/landing/CopyButton";
import { PUBLIC_RELEASE_TAG } from "@/lib/public-release";

export const metadata: Metadata = {
  title: "Documentation",
  description:
    "Install Phantom, connect Claude Code, Cursor, Windsurf, or Codex, and verify the local credential boundary with current open-source documentation.",
  alternates: { canonical: "/docs" },
  openGraph: {
    type: "website",
    siteName: "Phantom",
    title: "Phantom Documentation — Install, connect, and verify",
    description: "Install Phantom, connect Claude Code, Cursor, Windsurf, or Codex, and verify the local credential boundary with current open-source documentation.",
    url: "/docs",
    locale: "en_US",
    images: [{ url: "/og-image.png", width: 1200, height: 630, alt: "Phantom open-source documentation and credential boundary." }],
  },
  twitter: {
    card: "summary_large_image",
    site: "@ashlrai",
    creator: "@ashlrai",
    title: "Phantom Documentation — Install, connect, and verify",
    description: "Current installation, agent setup, platform, and security-boundary documentation for Phantom.",
    images: ["/og-image.png"],
  },
};

const COLLECTIONS = [
  {
    title: "Use Phantom",
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
            <h1>Secure API keys for AI coding agents.</h1>
            <p>
              Give an agent supported API access without placing the real key in
              its context. Start with one local project, verify the boundary,
              and expand only after the evidence matches your environment.
            </p>
            <div className="docs-page__command">
              <CopyButton text={"phantom init\nphantom agent doctor\nphantom exec -- claude"} />
            </div>
            <p className="docs-page__release">
              The reviewed public release is {PUBLIC_RELEASE_TAG}. Source may be
              ahead; follow the repository&apos;s release-state notice before choosing
              an install channel.
            </p>
          </div>
        </header>

        <section className="landing-frame docs-page__collections" aria-label="Documentation collections">
          {COLLECTIONS.map((collection) => (
            <article key={collection.title}>
              <h2 id={collection.id}>{collection.title}</h2>
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
              <h2>Send coding agents to the same canonical boundary.</h2>
            </div>
            <div>
              <p>
                The compact and full references are versioned in the repository
                and published with the site. They describe current commands,
                hard denials, platform evidence, and links to deeper sources.
              </p>
              <div className="docs-page__agent-links">
                <Link href="/llms.txt">Read llms.txt</Link>
                <Link href="/llms-full.txt">Read llms-full.txt</Link>
                <a href="https://github.com/ashlrai/phantom-secrets">Star the source on GitHub</a>
              </div>
            </div>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
