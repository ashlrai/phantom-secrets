import type { Metadata } from "next";
import { ArrowRight, Check, Lock, Shield } from "@/components/landing/Icons";
import { Nav } from "@/components/landing/Nav";
import { SiteFooter } from "@/components/landing/SiteFooter";

const title = "Security | Phantom";
const description =
  "Review Phantom's narrow security boundary, verification material, known limitations, and private vulnerability-reporting route.";

export const metadata: Metadata = {
  title: { absolute: title },
  description,
  alternates: { canonical: "https://phm.dev/security" },
  openGraph: {
    title,
    description,
    url: "https://phm.dev/security",
    type: "website",
    images: ["/og-image.png"],
  },
  twitter: {
    card: "summary_large_image",
    title,
    description,
    images: ["/og-image.png"],
  },
};

const BOUNDARIES = [
  {
    title: "Value-blind managed path",
    body: "Managed dotenv files contain phantom placeholders. On an exact configured route, the authenticated loopback proxy injects the route's vault value into its fixed authentication header.",
  },
  {
    title: "Local-first custody",
    body: "The shipped path stores credentials through an OS keychain or encrypted-file backend. Cloud and team source does not prove a commissioned hosted service.",
  },
  {
    title: "Explicitly narrow protection",
    body: "Phantom reduces accidental credential exposure in its managed workflow. It is not a sandbox, endpoint-security suite, identity provider, or regulatory certification.",
  },
] as const;

const LIMITS = [
  "Equivalent same-user shell, debugger, filesystem, or terminal-control authority can defeat the separation.",
  "A compromised operating system, administrator, replaced binary, or malicious dependency remains outside the boundary.",
  "Audit evidence is local by default and is not an independently signed or centrally retained record.",
  "Provider issuance and lifecycle operations are hard-denied in 0.7.5; source adapters and test mocks are not live integrations.",
  "Independent binary signatures, macOS notarization, Windows Authenticode, and regulatory certifications are not claimed.",
] as const;

const RESOURCES = [
  {
    title: "Threat model",
    body: "Trust boundaries, abuse cases, known gaps, and non-mitigations.",
    href: "https://github.com/ashlrai/phantom-secrets/blob/main/THREAT_MODEL.md",
  },
  {
    title: "Security policy",
    body: "Supported versions, disclosure expectations, scope, and safe harbor.",
    href: "https://github.com/ashlrai/phantom-secrets/blob/main/SECURITY.md",
  },
  {
    title: "Audit index",
    body: "Canonical map for technical, release, platform, and security review.",
    href: "https://github.com/ashlrai/phantom-secrets/blob/main/docs/audit-index.md",
  },
] as const;

export default function SecurityPage() {
  return (
    <>
      <Nav />
      <main id="main-content" tabIndex={-1}>
        <header className="relative overflow-hidden border-b border-border pb-20 pt-20 sm:pb-28 sm:pt-28">
          <div
            aria-hidden
            className="pointer-events-none absolute inset-0 -z-10"
            style={{
              background:
                "radial-gradient(ellipse 62% 62% at 50% 0%, rgba(34,197,94,0.10) 0%, rgba(59,130,246,0.10) 35%, transparent 72%)",
            }}
          />
          <div className="mx-auto max-w-[1050px] px-7">
            <div className="inline-flex items-center gap-2 rounded-full border border-border bg-s1/80 px-3 py-1.5 font-mono text-[0.7rem] uppercase tracking-[0.12em] text-t2">
              <Lock className="h-3.5 w-3.5 text-green" /> Security boundary
            </div>
            <h1 className="mt-7 max-w-[880px] text-[clamp(2.5rem,6vw,4.7rem)] font-extrabold leading-[0.98] tracking-[-0.052em] text-white">
              Verify the boundary before you trust it.
            </h1>
            <p className="mt-7 max-w-[720px] text-[1rem] leading-[1.75] text-t2 sm:text-[1.08rem]">
              Phantom addresses one hard problem: letting a supported agent
              workflow use configured API credentials without placing provider
              values in the managed dotenv context. The security case is open
              to inspection, and its limits are part of the product contract.
            </p>
            <div className="mt-9 flex flex-col gap-3 sm:flex-row">
              <a
                href="https://github.com/ashlrai/phantom-secrets/security/advisories/new"
                className="inline-flex min-h-[46px] items-center justify-center gap-2 rounded-lg bg-blue-action px-5 py-3 text-[0.9rem] font-semibold text-white no-underline transition hover:-translate-y-px hover:bg-blue-action-d"
              >
                Report privately <ArrowRight className="h-4 w-4" />
              </a>
              <a
                href="https://github.com/ashlrai/phantom-secrets/blob/main/THREAT_MODEL.md"
                className="inline-flex min-h-[46px] items-center justify-center rounded-lg border border-border-l px-5 py-3 text-[0.9rem] font-semibold text-t1 no-underline transition hover:border-t3"
              >
                Read the threat model
              </a>
            </div>
          </div>
        </header>

        <section className="py-20 sm:py-28">
          <div className="mx-auto max-w-[1100px] px-7">
            <div className="max-w-[690px]">
              <p className="font-mono text-[0.72rem] uppercase tracking-[0.14em] text-blue-b">
                What the shipped local path does
              </p>
              <h2 className="mt-4 text-[2rem] font-extrabold tracking-[-0.04em] text-white sm:text-[2.6rem]">
                A smaller credential surface for agent-driven work.
              </h2>
            </div>
            <div className="mt-10 grid gap-4 lg:grid-cols-3">
              {BOUNDARIES.map((item, index) => (
                <article key={item.title} className="rounded-2xl border border-border bg-s1 p-7">
                  <span className="font-mono text-[0.75rem] text-blue-b">0{index + 1}</span>
                  <h3 className="mt-5 text-[1.05rem] font-bold text-t1">{item.title}</h3>
                  <p className="mt-3 text-[0.9rem] leading-[1.7] text-t2">{item.body}</p>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section className="border-y border-border bg-s1/30 py-20 sm:py-24">
          <div className="mx-auto grid max-w-[1100px] gap-12 px-7 lg:grid-cols-[0.9fr_1.1fr]">
            <div>
              <Shield className="h-8 w-8 text-blue-b" />
              <h2 className="mt-6 text-[1.9rem] font-extrabold tracking-[-0.035em] text-white">
                Known limits are review inputs.
              </h2>
              <p className="mt-4 text-[0.9rem] leading-[1.7] text-t2">
                These summaries do not replace the versioned threat model.
                Review the exact installed artifact, configuration, endpoint,
                and client before adoption.
              </p>
            </div>
            <ul className="space-y-3">
              {LIMITS.map((item) => (
                <li key={item} className="flex gap-3 rounded-xl border border-border bg-bg/60 p-5 text-[0.88rem] leading-[1.6] text-t2">
                  <Check className="mt-1 h-4 w-4 shrink-0 text-t3" />
                  {item}
                </li>
              ))}
            </ul>
          </div>
        </section>

        <section className="py-20 sm:py-24">
          <div className="mx-auto max-w-[1100px] px-7">
            <p className="font-mono text-[0.72rem] uppercase tracking-[0.14em] text-t3">
              Evidence, not badges
            </p>
            <h2 className="mt-4 text-[1.9rem] font-extrabold tracking-[-0.035em] text-white">
              Start your review in the canonical sources.
            </h2>
            <div className="mt-8 grid gap-4 md:grid-cols-3">
              {RESOURCES.map((item) => (
                <a key={item.title} href={item.href} className="group rounded-2xl border border-border bg-s1 p-6 no-underline transition hover:-translate-y-0.5 hover:border-blue-d/70">
                  <div className="flex items-center justify-between gap-4">
                    <h3 className="font-bold text-t1">{item.title}</h3>
                    <ArrowRight className="h-4 w-4 text-t3 transition group-hover:translate-x-0.5 group-hover:text-blue-b" />
                  </div>
                  <p className="mt-3 text-[0.86rem] leading-[1.65] text-t2">{item.body}</p>
                </a>
              ))}
            </div>
            <p className="mt-8 text-[0.82rem] leading-[1.65] text-t3">
              Phantom has no paid bug bounty and claims no certification or
              independent security audit. Report suspected vulnerabilities
              privately; do not include real credentials or personal data.
            </p>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
