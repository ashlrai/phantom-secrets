import type { Metadata } from "next";
import Link from "next/link";
import { Nav } from "@/components/landing/Nav";
import { SiteFooter } from "@/components/landing/SiteFooter";

const title = "Phantom ecosystem — open tools that make engineering agents useful";
const description =
  "Phantom is the command center. Phantom Secrets, Locus, Lexicon, AshlrCode and Morphkit each solve one part of agent work: secrets, account identity, voice vocabulary, a coding CLI and web-to-SwiftUI.";

export const metadata: Metadata = {
  title: { absolute: title },
  description,
  alternates: { canonical: "https://phm.dev/ecosystem" },
  openGraph: {
    type: "website",
    siteName: "Phantom",
    url: "https://phm.dev/ecosystem",
    title,
    description,
    images: [{ url: "/workbench-og.png", width: 1200, height: 630, alt: "The Phantom engineering ecosystem by AshlrAI." }],
  },
  twitter: { card: "summary_large_image", title: "Phantom ecosystem", description, images: ["/workbench-og.png"] },
};

const projects = [
  { name: "Phantom", role: "Command center", repo: "phantom", href: "/", body: "One workbench for coding-agent seats, local models, a Leader, and a fleet bounded by signed authority." },
  { name: "Phantom Secrets", role: "Secret boundary", repo: "phantom-secrets", href: "/secrets", body: "Keep real secrets out of agent prompts by giving tools local, replaceable handles instead." },
  { name: "Locus", role: "Account identity", repo: "locus", body: "Bind agent tools to the intended account and tenant before a command can act." },
  { name: "Lexicon", role: "Voice vocabulary", repo: "lexicon", body: "Correct the names and technical words speech recognition gets wrong before they reach an agent." },
  { name: "AshlrCode", role: "Coding agent CLI", repo: "ashlrcode", body: "Work in the terminal with a coding agent that can use tools, skills, and multiple model providers." },
  { name: "Morphkit", role: "Web to SwiftUI", repo: "morphkit", body: "Translate a TypeScript or React app into a native SwiftUI starting point for iOS." },
] as const;

const structuredData = {
  "@context": "https://schema.org",
  "@type": "CollectionPage",
  name: "Phantom engineering ecosystem",
  url: "https://phm.dev/ecosystem",
  description,
  hasPart: projects.map((p) => ({
    "@type": "SoftwareSourceCode",
    name: p.name,
    codeRepository: `https://github.com/ashlrai/${p.repo}`,
    description: p.body,
  })),
};

export default function EcosystemPage() {
  return (
    <>
      <Nav />
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(structuredData) }} />
      <main id="main-content" tabIndex={-1} className="phantom-workbench-surface">
        <div className="phantom-home-content">
          <section className="phantom-secrets-bridge" aria-labelledby="ecosystem-title">
            <p>Phantom / open engineering</p>
            <h1 id="ecosystem-title">Tools that make agents useful.</h1>
            <p>
              Phantom is the command center. The other repositories solve specific parts of the work: keeping secrets
              out of model context, binding the right account, turning voice into usable instructions, coding across
              providers, and moving a web app to native SwiftUI. Each is its own public project.
            </p>
            <div className="phantom-workbench__actions">
              <Link href="/">Explore Phantom</Link>
              <a href="https://github.com/ashlrai/phantom">Phantom on GitHub</a>
            </div>
          </section>

          <section className="phantom-secrets-bridge" aria-labelledby="projects-title">
            <h2 id="projects-title">Pick the right tool.</h2>
            <p>Independent projects with different jobs. Start with the one that solves your immediate problem.</p>
            <ol>
              {projects.map((p) => (
                <li key={p.repo} id={p.repo}>
                  <h3>{p.name} <small>· {p.role}</small></h3>
                  <p>{p.body}</p>
                  <div className="phantom-workbench__actions">
                    {"href" in p ? <Link href={p.href}>{p.name} on PHM.dev →</Link> : null}
                    <a href={`https://github.com/ashlrai/${p.repo}`}>Source on GitHub →</a>
                  </div>
                </li>
              ))}
            </ol>
          </section>

          <section className="phantom-secrets-bridge" aria-labelledby="start-title">
            <h2 id="start-title">Start building in Phantom.</h2>
            <p>Install the CLI, open the console, and follow the guide for your first seat.</p>
            <div className="phantom-workbench__actions">
              <Link href="/">Install Phantom</Link>
              <Link href="/docs">Read the docs</Link>
              <a href="https://github.com/orgs/ashlrai/repositories">Browse all public repositories</a>
            </div>
            <p>
              Each repository has its own source, issues, and contribution path. 
            </p>
          </section>
        </div>
      </main>
      <SiteFooter />
    </>
  );
}
