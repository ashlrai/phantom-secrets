import type { Metadata } from "next";
import Link from "next/link";
import { Nav } from "@/components/landing/Nav";
import { SiteFooter } from "@/components/landing/SiteFooter";
import { SecretsSoftwareApplication } from "@/components/landing/LandingStructuredData";
import { PUBLIC_RELEASE_TAG, PUBLIC_RELEASE_URL } from "@/lib/public-release";

const title = "Phantom Secrets capabilities and installation";
const description = "Install the free, MIT-licensed Phantom Secrets CLI on macOS, Linux or Windows. Inspect supported credential workflows, connect an MCP client and understand the limits.";
const canonical = "/secrets/capabilities";

export const metadata: Metadata = {
  title: { absolute: title },
  description,
  alternates: { canonical },
  openGraph: {
    type: "website",
    siteName: "Phantom",
    title,
    description,
    url: canonical,
    images: [{ url: "/og-image.png", width: 1200, height: 630, alt: title }],
  },
  twitter: { card: "summary_large_image", title, description, images: ["/og-image.png"] },
};

const capabilities = [
  ["Protect project secrets", "Move managed dotenv values into a local vault. Persistent phm_ mappings remain sensitive metadata; do not disclose or publish them."],
  ["Run supported API work", "An authenticated local proxy injects a matched route's vault value into its fixed authentication header. Client headers and request bodies never resolve mappings."],
  ["Inspect through MCP", "Use value-blind inventory and diagnostics. Read the runtime tools/list schema for exact parameters; plaintext secret submission through MCP is refused."],
  ["Connect coding clients", "Generate local MCP configuration for Claude Code, Cursor, Windsurf or Codex. Gemini CLI supports status inspection only in the pinned release; newer source may differ."],
  ["Keep an audit trail", "Optional local audit records track secret names and operations, never values. Chain verification checks integrity; it does not establish compliance certification."],
];

export default function CapabilitiesPage() {
  return (
    <>
      <Nav />
      <SecretsSoftwareApplication />
      <main id="main-content" tabIndex={-1} className="docs-page docs-article-page">
        <header className="docs-article-page__masthead">
          <div className="landing-frame docs-article-page__masthead-layout">
            <p className="docs-article-page__summary">Phantom Secrets {PUBLIC_RELEASE_TAG}. Free local CLI. MIT licensed.</p>
            <nav aria-label="Breadcrumb" className="docs-article-page__breadcrumb">
              <Link href="/secrets">Phantom Secrets</Link>
              <span aria-hidden="true">/</span>
              <span aria-current="page">Capabilities and installation</span>
            </nav>
          </div>
        </header>

        <div className="landing-frame docs-article-page__layout">
          <article className="docs-article">
            <h1>Capabilities and installation</h1>
            <p>
              Give supported AI workflows access to APIs while keeping managed credential
              values behind a local boundary. The Secrets executable is <code>phantom</code>.
              The separate <Link href="/docs/workbench">Phantom Workbench</Link> uses <code>phm</code>.
            </p>

            <h2 id="capabilities">What the local CLI can do</h2>
            <dl className="divide-y divide-[var(--rule)]">
              {capabilities.map(([name, detail]) => (
                <div key={name} className="grid gap-2 py-5 sm:grid-cols-[11rem_1fr] sm:gap-6">
                  <dt className="font-semibold text-[var(--ink)]">{name}</dt>
                  <dd>{detail}</dd>
                </div>
              ))}
            </dl>

            <h2 id="install">Install a reviewed release</h2>
            <ol>
              <li>
                Open the <a href={PUBLIC_RELEASE_URL}>immutable {PUBLIC_RELEASE_TAG} GitHub release</a>.
                Choose the archive matching macOS, Linux or Windows and your ARM64 or x86_64 architecture.
                Download its adjacent <code>.sha256</code> sidecar and verify the archive before extraction.
              </li>
              <li>
                Put both <code>phantom</code> and <code>phantom-mcp</code> executables on PATH
                (with <code>.exe</code> on Windows). See the <Link href="/secrets#install">platform installer and checksum instructions</Link>.
                The GitHub release receipt is separate from package-registry publication.
              </li>
              <li>
                Verify the installed versions before protecting a project:
                <pre><code>{"phantom --version\nphantom-mcp --version"}</code></pre>
                Both should report {PUBLIC_RELEASE_TAG}. Linux defaults to a session-persistent,
                non-reboot-persistent keyutils backend; configure the encrypted-file backend before
                initialization if you need persistence. Review <Link href="/docs/platform-support">platform support</Link> first.
              </li>
            </ol>

            <h2 id="connect">Protect a project and connect an agent</h2>
            <p>
              In your own terminal, run <code>phantom init</code> in the project root to store
              detected values and rewrite the managed dotenv file. Never paste real credentials
              into chat. Preview the client configuration before writing it:
            </p>
            <pre><code>{"phantom setup --client codex --print\nphantom setup --client codex\nphantom setup --status\nphantom exec -- codex"}</code></pre>
            <p>
              Substitute <code>claude</code>, <code>cursor</code> or <code>windsurf</code> for
              your client. Setup verifies a local MCP runtime and fails closed if it cannot find one.
              It does not download an unpinned package. Read the <Link href="/docs/delegation-quickstart">safe delegation quickstart</Link> before delegating credentialed work.
            </p>

            <h2 id="verify">Verify without reading secret values</h2>
            <pre><code>{"phantom status\nphantom doctor\nphantom why OPENAI_API_KEY --json"}</code></pre>
            <p>
              The key name above is an example, not a credential. These commands inspect local
              configuration without displaying vault values. If <code>exec.delivery</code> is <code>no_route</code>,
              there is no supported proxy route for that key. A locked vault is not an empty vault.
              Follow <Link href="/docs/troubleshooting">troubleshooting</Link> without printing secrets.
            </p>

            <h2 id="limits">Understand the boundary</h2>
            <p>
              Unmanaged files, same-user processes, a stolen proxy bearer and provider-generated
              content remain outside this protection. API requests still leave the machine.
              This is not a process sandbox or a guarantee that every SDK or database protocol works.
            </p>
            <p>
              MCP effects are disabled by default. Credential use, provider requests and persistent
              effects require the documented trusted-terminal approval gates outside agent authority.
              Agents must not emulate that ceremony. Live provider rotation is hard-denied in {PUBLIC_RELEASE_TAG}.
            </p>
            <p>
              The local CLI is free. Cloud and team clients require a separately commissioned
              hosted service and entitlement. Source availability does not establish service availability,
              certification or customer acceptance. See <Link href="/pricing">pricing and availability</Link>.
            </p>
          </article>

          <aside className="docs-article-page__aside" aria-label="Guide navigation">
            <h2 className="text-lg font-semibold text-[var(--ink)]">In this guide</h2>
            <a href="#capabilities">Local capabilities</a>
            <a href="#install">Install</a>
            <a href="#connect">Connect an agent</a>
            <a href="#verify">Verify</a>
            <a href="#limits">Trust boundary</a>
            <Link href="/docs">All documentation</Link>
            <a href="/llms.txt">Agent reference</a>
            <a href="https://github.com/ashlrai/phantom-secrets">View the source on GitHub</a>
          </aside>
        </div>
      </main>
      <SiteFooter />
    </>
  );
}
