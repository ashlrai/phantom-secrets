import type { Metadata } from "next";
import { ArrowRight, Check, Shield, Terminal } from "@/components/landing/Icons";
import { Nav } from "@/components/landing/Nav";
import { SiteFooter } from "@/components/landing/SiteFooter";
import { COMMERCIAL_CONTACT } from "@/lib/commercial-offerings";

const title = "Government evaluations | Phantom";
const description =
  "Evidence-first, written-scope evaluation of Phantom's MIT-licensed local-first workflow for public-sector environments.";

export const metadata: Metadata = {
  title: { absolute: title },
  description,
  alternates: { canonical: "https://phm.dev/government" },
  openGraph: {
    title,
    description,
    url: "https://phm.dev/government",
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

const EVIDENCE = [
  "Exact source, version, platform, and installation method",
  "Named workflow, data boundary, owners, and prohibited actions",
  "Test commands, results, skipped gates, and unresolved findings",
  "Separate records for deployment, provider, and user acceptance",
] as const;

const NON_CLAIMS = [
  "Phantom is not represented as FedRAMP authorized or FIPS validated.",
  "No SOC 2, ISO 27001, CMMC, HIPAA, PCI DSS, or agency authorization is claimed.",
  "No government contract vehicle or procurement schedule is represented on this site.",
  "No generally available hosted service, SSO/SAML, SCIM, or self-hosted enterprise control plane is offered.",
  "No uptime, response, residency, or support commitment exists outside a signed agreement.",
] as const;

export default function GovernmentPage() {
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
                "radial-gradient(ellipse 70% 60% at 50% -5%, rgba(96,165,250,0.18) 0%, transparent 72%)",
            }}
          />
          <div className="mx-auto max-w-[1050px] px-7">
            <div className="inline-flex items-center gap-2 rounded-full border border-border bg-s1/80 px-3 py-1.5 font-mono text-[0.7rem] uppercase tracking-[0.12em] text-t2">
              <Shield className="h-3.5 w-3.5 text-blue-b" /> Public-sector evaluation
            </div>
            <h1 className="mt-7 max-w-[880px] text-[clamp(2.5rem,6vw,4.7rem)] font-extrabold leading-[0.98] tracking-[-0.052em] text-white">
              Evidence first. Claims only as strong as the proof.
            </h1>
            <p className="mt-7 max-w-[720px] text-[1rem] leading-[1.75] text-t2 sm:text-[1.08rem]">
              Public-sector teams can use the MIT-licensed local core or
              discuss a bounded, written-scope evaluation with Ashlr AI. The
              evaluation starts with a named non-production environment and
              ends with an auditable decision—not a blanket authorization.
            </p>
            <div className="mt-9 flex flex-col gap-3 sm:flex-row">
              <a
                href={`mailto:${COMMERCIAL_CONTACT}?subject=Phantom%20government%20evaluation`}
                className="inline-flex min-h-[46px] items-center justify-center gap-2 rounded-lg bg-blue px-5 py-3 text-[0.9rem] font-semibold text-white no-underline transition hover:-translate-y-px hover:bg-blue-d"
              >
                Discuss requirements <ArrowRight className="h-4 w-4" />
              </a>
              <a
                href="https://github.com/ashlrai/phantom-secrets/blob/main/docs/government-evaluation.md"
                className="inline-flex min-h-[46px] items-center justify-center rounded-lg border border-border-l px-5 py-3 text-[0.9rem] font-semibold text-t1 no-underline transition hover:border-t3"
              >
                Read the evaluation guide
              </a>
            </div>
          </div>
        </header>

        <section className="py-20 sm:py-28">
          <div className="mx-auto grid max-w-[1100px] gap-12 px-7 lg:grid-cols-2">
            <div>
              <p className="font-mono text-[0.72rem] uppercase tracking-[0.14em] text-blue-b">
                Evaluation boundary
              </p>
              <h2 className="mt-4 text-[2rem] font-extrabold tracking-[-0.04em] text-white sm:text-[2.6rem]">
                Start local. Keep authority explicit.
              </h2>
              <p className="mt-5 text-[0.92rem] leading-[1.75] text-t2">
                Phantom is designed to keep provider values out of the managed
                agent dotenv path. That narrow control does not make the agent,
                endpoint, network, or organization compliant. Reviewers should
                evaluate the complete operating environment and the documented
                same-user authority limitation.
              </p>
              <a
                href="https://github.com/ashlrai/phantom-secrets/blob/main/THREAT_MODEL.md"
                className="mt-6 inline-flex items-center gap-2 text-[0.88rem] font-semibold text-blue-b no-underline hover:text-blue"
              >
                Review the threat model <ArrowRight className="h-4 w-4" />
              </a>
            </div>
            <div className="rounded-2xl border border-border bg-s1 p-7">
              <div className="flex items-center gap-3">
                <Terminal className="h-5 w-5 text-blue-b" />
                <h3 className="font-bold text-t1">Minimum evidence packet</h3>
              </div>
              <ul className="mt-6 space-y-4">
                {EVIDENCE.map((item) => (
                  <li key={item} className="flex gap-3 text-[0.9rem] leading-[1.6] text-t2">
                    <Check className="mt-1 h-4 w-4 shrink-0 text-green" strokeWidth={2.6} />
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </section>

        <section className="border-y border-border bg-s1/30 py-20 sm:py-24">
          <div className="mx-auto max-w-[1000px] px-7">
            <p className="font-mono text-[0.72rem] uppercase tracking-[0.14em] text-t3">
              Diligence starts here
            </p>
            <h2 className="mt-4 max-w-[700px] text-[1.9rem] font-extrabold tracking-[-0.035em] text-white">
              No implied authorization, certification, or contract vehicle.
            </h2>
            <div className="mt-8 grid gap-3 sm:grid-cols-2">
              {NON_CLAIMS.map((claim) => (
                <div key={claim} className="rounded-xl border border-border bg-bg/60 p-5 text-[0.88rem] leading-[1.65] text-t2">
                  {claim}
                </div>
              ))}
            </div>
            <p className="mt-7 text-[0.82rem] leading-[1.65] text-t3">
              Requested controls may be discussed as proposed engineering work.
              A proposal is not implementation; implementation is not
              deployment; deployment is not agency authorization or acceptance.
            </p>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
