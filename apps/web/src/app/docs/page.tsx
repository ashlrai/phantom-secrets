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
  openGraph: { url: "/docs" },
};

const COLLECTIONS = [
  {
    title: "Use Phantom",
    links: [
      ["Complete getting started guide", "docs/getting-started.md"],
      ["Safe delegation quickstart", "docs/delegation-quickstart.md"],
      ["Documentation map", "docs/README.md"],
      ["Troubleshooting", "docs/troubleshooting.md"],
    ],
  },
  {
    title: "Connect an agent",
    links: [
      ["Claude Code", "docs/claude-code.md"],
      ["Cursor", "docs/cursor.md"],
      ["Windsurf", "docs/windsurf.md"],
      ["Codex", "docs/codex.md"],
    ],
  },
  {
    title: "Evaluate trust",
    links: [
      ["Security model", "SECURITY.md"],
      ["Threat model", "THREAT_MODEL.md"],
      ["Architecture", "docs/architecture.md"],
      ["Platform support", "docs/platform-support.md"],
    ],
  },
  {
    title: "Adopt and contribute",
    links: [
      ["Enterprise adoption", "docs/enterprise-adoption.md"],
      ["Government evaluation", "docs/government-evaluation.md"],
      ["Contributing", "CONTRIBUTING.md"],
      ["Project roadmap", "ROADMAP.md"],
    ],
  },
] as const;

const REPO = "https://github.com/ashlrai/phantom-secrets/blob/main/";

export default function DocsPage() {
  return (
    <>
      <Nav />
      <main id="main-content" tabIndex={-1} className="docs-page">
        <header className="docs-page__hero">
          <div className="landing-frame">
            <p className="landing-kicker">Phantom documentation</p>
            <h1>Give an agent capability without handing it the key.</h1>
            <p>
              Start with one local project. Verify what crosses the boundary,
              connect your coding client, and expand only after the evidence
              matches your environment.
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
              <h2>{collection.title}</h2>
              <ul>
                {collection.links.map(([label, path]) => (
                  <li key={path}>
                    <a href={`${REPO}${path}`}>{label}</a>
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
