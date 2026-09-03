import type { Metadata } from "next";
import { Nav } from "@/components/landing/Nav";
import { SiteFooter } from "@/components/landing/SiteFooter";
import { Check } from "@/components/landing/Icons";
import { FAQ } from "@/components/landing/FAQ";
import { Comparison } from "@/components/landing/Comparison";
import {
  COMMERCIAL_INTAKE,
  COMMERCIAL_NON_CLAIMS,
  COMMERCIAL_OFFERINGS,
} from "@/lib/commercial-offerings";

const title = "Open source and commercial offerings | Phantom";
const description =
  "Use Phantom's MIT-licensed local-first core for free, or scope enterprise evaluation, integration, and support services with Ashlr AI.";

export const metadata: Metadata = {
  title: { absolute: title },
  description,
  alternates: { canonical: "https://phm.dev/pricing" },
  openGraph: {
    title,
    description,
    url: "https://phm.dev/pricing",
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

export default function PricingPage() {
  return (
    <>
      <Nav />
      <main id="main-content" tabIndex={-1}>
        {/* Hero */}
        <header className="relative pt-20 pb-14 sm:pt-28 sm:pb-20 overflow-hidden">
          <div
            aria-hidden
            className="pointer-events-none absolute inset-x-0 top-0 h-[520px] -z-10 opacity-50"
            style={{
              background:
                "radial-gradient(ellipse 60% 60% at 50% 0%, rgba(59,130,246,0.16) 0%, transparent 70%)",
            }}
          />

          <div className="mx-auto max-w-[940px] px-7 text-center">
            <span className="inline-flex items-center gap-2 rounded-full border border-border bg-s1/80 px-3 py-1 text-[0.72rem] font-medium text-t2 backdrop-blur-md">
              MIT-licensed core · commercial services by agreement
            </span>

            <h1 className="mt-7 font-extrabold tracking-[-0.04em] leading-[1.04] text-white text-[clamp(2.2rem,5.4vw,3.8rem)]">
              Open source without a gate.
              <br />
              <span className="bg-gradient-to-br from-blue-b via-blue to-blue-d bg-clip-text text-transparent">
                Expert help with a written scope.
              </span>
            </h1>

            <p className="mt-6 mx-auto max-w-[600px] text-[0.98rem] sm:text-[1.04rem] leading-[1.65] text-t2">
              Use the local-first core under MIT. Contract separately for an
              enterprise or government evaluation, integration work, and
              support commitments tailored to a named environment.
            </p>
          </div>
        </header>

        {/* Tier cards */}
        <section className="pb-20 sm:pb-28">
          <div className="mx-auto max-w-[1100px] px-7">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              {COMMERCIAL_OFFERINGS.map((t) => (
                  <article
                    key={t.name}
                    className={
                      "relative rounded-2xl border bg-s1 p-7 flex flex-col " +
                      (t.featured
                        ? "border-blue-d/70 shadow-[0_0_60px_-20px_rgba(59,130,246,0.45)]"
                        : "border-border")
                    }
                  >
                    {t.featured && (
                      <span className="absolute -top-2.5 left-7 rounded-full border border-blue-d/40 bg-blue px-2.5 py-0.5 text-[0.7rem] font-bold uppercase tracking-[0.12em] text-white">
                        Written scope
                      </span>
                    )}

                    <div className={`flex items-baseline justify-between ${t.featured ? "mt-3" : ""}`}>
                      <h2 className="text-[1.05rem] font-bold text-t1">{t.name}</h2>
                    </div>

                    <div className="mt-3 flex items-baseline gap-1">
                      <span className="text-[2.4rem] font-extrabold tracking-[-0.04em] text-white leading-none">
                        {t.price}
                      </span>
                      {t.cadence && (
                        <span className="text-[0.85rem] text-t3">{t.cadence}</span>
                      )}
                    </div>

                    <p className="mt-3 text-[0.85rem] text-t2 leading-[1.55]">
                      {t.pitch}
                    </p>

                    <ul className="mt-5 space-y-2 flex-1">
                      {t.features.map((f) => (
                        <li
                          key={f}
                          className="flex items-start gap-2 text-[0.86rem] text-t2"
                        >
                          <Check
                            className="mt-[3px] h-3.5 w-3.5 shrink-0 text-blue-b"
                            strokeWidth={2.4}
                          />
                          <span>{f}</span>
                        </li>
                      ))}
                    </ul>

                    <a
                      href={t.cta.href}
                      className="mt-6 inline-flex items-center justify-center min-h-[44px] rounded-lg border border-border-l px-4 py-2.5 text-[0.88rem] font-semibold text-t1 no-underline transition-colors duration-200 hover:border-t3"
                    >
                      {t.cta.label}
                    </a>
                  </article>
              ))}
            </div>

            <p className="mt-10 text-center text-[0.82rem] text-t3 max-w-[680px] mx-auto leading-[1.7]">
              The MIT License already grants the core software rights. A
              commercial agreement covers only its stated services,
              deliverables, support commitments, and acceptance criteria.
            </p>
          </div>
        </section>

        <section className="border-y border-border bg-s1/30 py-20 sm:py-24">
          <div className="mx-auto grid max-w-[1100px] gap-10 px-7 lg:grid-cols-2">
            <div>
              <p className="font-mono text-[0.72rem] uppercase tracking-[0.14em] text-blue-b">
                A useful first conversation
              </p>
              <h2 className="mt-4 text-[1.8rem] font-extrabold tracking-[-0.035em] text-white sm:text-[2.3rem]">
                Bring a concrete environment, not a blank check.
              </h2>
              <p className="mt-4 max-w-[560px] text-[0.95rem] leading-[1.7] text-t2">
                We start with a reversible, non-production workflow and define
                what evidence would justify the next decision. Scope, price,
                schedule, and support terms exist only when written and agreed.
              </p>
            </div>
            <ol className="grid gap-3">
              {COMMERCIAL_INTAKE.map((item, index) => (
                <li
                  key={item}
                  className="flex gap-4 rounded-xl border border-border bg-s1 p-4 text-[0.9rem] leading-[1.55] text-t2"
                >
                  <span className="font-mono text-blue-b">0{index + 1}</span>
                  {item}
                </li>
              ))}
            </ol>
          </div>
        </section>

        <section className="py-20 sm:py-24">
          <div className="mx-auto max-w-[920px] px-7">
            <p className="font-mono text-[0.72rem] uppercase tracking-[0.14em] text-t3">
              Current commercial boundary
            </p>
            <h2 className="mt-4 text-[1.7rem] font-extrabold tracking-[-0.03em] text-white">
              What this site does not promise
            </h2>
            <div className="mt-7 grid gap-3 sm:grid-cols-2">
              {COMMERCIAL_NON_CLAIMS.map((claim) => (
                <div
                  key={claim}
                  className="rounded-xl border border-border bg-s1 p-5 text-[0.88rem] leading-[1.6] text-t2"
                >
                  {claim}
                </div>
              ))}
            </div>
            <p className="mt-6 text-[0.82rem] leading-[1.65] text-t3">
              A source implementation or passing test does not prove a hosted
              service, external certification, provider commissioning, or
              customer acceptance. Those require their own evidence.
            </p>
          </div>
        </section>

        <Comparison />
        <FAQ />
      </main>
      <SiteFooter />
    </>
  );
}
