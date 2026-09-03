import type { Metadata } from "next";
import { ArrowRight, Check, Code, Shield, Terminal } from "@/components/landing/Icons";
import { Nav } from "@/components/landing/Nav";
import { SiteFooter } from "@/components/landing/SiteFooter";
import {
  COMMERCIAL_CONTACT,
  COMMERCIAL_NON_CLAIMS,
} from "@/lib/commercial-offerings";

const title = "Enterprise evaluations | Phantom";
const description =
  "Written-scope Phantom evaluations, integration work, and support around the MIT-licensed local-first core.";

export const metadata: Metadata = {
  title: { absolute: title },
  description,
  alternates: { canonical: "https://phm.dev/enterprise" },
  openGraph: {
    title,
    description,
    url: "https://phm.dev/enterprise",
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

const WORKSTREAMS = [
  {
    title: "Adoption evaluation",
    body: "Select a reversible, non-production workflow; define success, exclusions, owners, and evidence before work begins.",
    icon: Terminal,
  },
  {
    title: "Integration engineering",
    body: "Integrate the shipped local workflow with named repositories, operating systems, and supported AI clients.",
    icon: Code,
  },
  {
    title: "Security review",
    body: "Map Phantom's documented trust boundaries and known gaps to the controls your reviewers actually require.",
    icon: Shield,
  },
] as const;

const PROCESS = [
  "Confirm that the shipped local-first boundary matches the problem.",
  "Write the scope, exclusions, deliverables, price, schedule, and acceptance tests.",
  "Implement and validate against an exact source and environment.",
  "Close with evidence, unresolved risks, and an explicit adoption decision.",
] as const;

export default function EnterprisePage() {
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
                "radial-gradient(ellipse 70% 65% at 50% -10%, rgba(59,130,246,0.20) 0%, transparent 70%)",
            }}
          />
          <div className="mx-auto max-w-[1050px] px-7">
            <p className="font-mono text-[0.72rem] uppercase tracking-[0.16em] text-blue-b">
              Enterprise services
            </p>
            <h1 className="mt-6 max-w-[820px] text-[clamp(2.5rem,6vw,4.7rem)] font-extrabold leading-[0.98] tracking-[-0.052em] text-white">
              Adopt the MIT core. Contract for the work around it.
            </h1>
            <p className="mt-7 max-w-[700px] text-[1rem] leading-[1.75] text-t2 sm:text-[1.08rem]">
              Phantom&apos;s CLI, local vault, proxy, and MCP server remain open
              source. Ashlr AI can discuss a written-scope evaluation,
              environment-specific integration, and support commitments. The
              agreement does not take away rights already granted by MIT.
            </p>
            <div className="mt-9 flex flex-col gap-3 sm:flex-row">
              <a
                href={`mailto:${COMMERCIAL_CONTACT}?subject=Phantom%20enterprise%20evaluation`}
                className="inline-flex min-h-[46px] items-center justify-center gap-2 rounded-lg bg-blue-action px-5 py-3 text-[0.9rem] font-semibold text-white no-underline transition hover:-translate-y-px hover:bg-blue-action-d"
              >
                Scope an evaluation <ArrowRight className="h-4 w-4" />
              </a>
              <a
                href="https://github.com/ashlrai/phantom-secrets/blob/main/docs/enterprise-adoption.md"
                className="inline-flex min-h-[46px] items-center justify-center rounded-lg border border-border-l px-5 py-3 text-[0.9rem] font-semibold text-t1 no-underline transition hover:border-t3"
              >
                Read the adoption guide
              </a>
            </div>
          </div>
        </header>

        <section className="py-20 sm:py-28">
          <div className="mx-auto max-w-[1100px] px-7">
            <div className="max-w-[680px]">
              <p className="font-mono text-[0.72rem] uppercase tracking-[0.14em] text-t3">
                Purchasable by written agreement
              </p>
              <h2 className="mt-4 text-[2rem] font-extrabold tracking-[-0.04em] text-white sm:text-[2.6rem]">
                A precise engagement, built around your acceptance gate.
              </h2>
            </div>
            <div className="mt-10 grid gap-4 lg:grid-cols-3">
              {WORKSTREAMS.map(({ title, body, icon: Icon }) => (
                <article key={title} className="rounded-2xl border border-border bg-s1 p-7">
                  <span className="inline-flex h-10 w-10 items-center justify-center rounded-lg border border-blue-d/40 bg-blue/10 text-blue-b">
                    <Icon className="h-5 w-5" />
                  </span>
                  <h3 className="mt-6 text-[1.05rem] font-bold text-t1">{title}</h3>
                  <p className="mt-3 text-[0.9rem] leading-[1.7] text-t2">{body}</p>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section className="border-y border-border bg-s1/30 py-20 sm:py-24">
          <div className="mx-auto grid max-w-[1100px] gap-12 px-7 lg:grid-cols-[0.8fr_1.2fr]">
            <div>
              <p className="font-mono text-[0.72rem] uppercase tracking-[0.14em] text-blue-b">
                How it starts
              </p>
              <h2 className="mt-4 text-[1.8rem] font-extrabold tracking-[-0.035em] text-white">
                One bounded workflow. Evidence at every gate.
              </h2>
              <p className="mt-4 text-[0.9rem] leading-[1.7] text-t2">
                A successful source review is not a rollout. Each engagement
                separates proposal, implementation, verification, environment
                commissioning, and customer acceptance.
              </p>
            </div>
            <ol className="grid gap-3">
              {PROCESS.map((item, index) => (
                <li key={item} className="flex gap-4 rounded-xl border border-border bg-bg/60 p-5">
                  <span className="font-mono text-[0.78rem] text-blue-b">0{index + 1}</span>
                  <span className="text-[0.9rem] leading-[1.6] text-t2">{item}</span>
                </li>
              ))}
            </ol>
          </div>
        </section>

        <section className="py-20 sm:py-24">
          <div className="mx-auto max-w-[1000px] px-7">
            <div className="rounded-2xl border border-border bg-s1 p-7 sm:p-10">
              <p className="font-mono text-[0.72rem] uppercase tracking-[0.14em] text-t3">
                Clear before procurement
              </p>
              <h2 className="mt-4 text-[1.7rem] font-extrabold tracking-[-0.03em] text-white">
                Capabilities we do not sell as live today
              </h2>
              <ul className="mt-7 grid gap-3 sm:grid-cols-2">
                {COMMERCIAL_NON_CLAIMS.map((claim) => (
                  <li key={claim} className="flex gap-3 text-[0.88rem] leading-[1.6] text-t2">
                    <Check className="mt-1 h-4 w-4 shrink-0 text-t3" />
                    {claim}
                  </li>
                ))}
              </ul>
              <p className="mt-7 border-t border-border pt-6 text-[0.82rem] leading-[1.65] text-t3">
                Requested product work can be scoped as proposed work. It is
                not represented as shipped, certified, commissioned, or
                accepted until separate evidence proves that state.
              </p>
            </div>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
