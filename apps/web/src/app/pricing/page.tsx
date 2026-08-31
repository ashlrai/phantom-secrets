"use client";

import { posthog } from "@/lib/posthog";
import { Nav } from "@/components/landing/Nav";
import { SiteFooter } from "@/components/landing/SiteFooter";
import { Check } from "@/components/landing/Icons";
import { FAQ } from "@/components/landing/FAQ";
import { Comparison } from "@/components/landing/Comparison";

type Tier = {
  name: string;
  price: string;
  cadence: string;
  pitch: string;
  featured: boolean;
  features: string[];
  cta: { label: string; href: string };
};

const TIERS: Tier[] = [
  {
    name: "Free",
    price: "$0",
    cadence: "/mo",
    pitch: "Local-first. Open source. Forever.",
    featured: false,
    features: [
      "Local vault (OS keychain or encrypted file)",
      "Local proxy: requests are size-bounded and buffered; responses can stream",
      "MCP server for supported clients",
      "Agent readiness CLI · MCP tool catalog",
      "Unlimited local secrets",
      "Vercel & Railway sync with local platform tokens",
    ],
    cta: {
      label: "Install free",
      href: "https://github.com/ashlrai/phantom-secrets",
    },
  },
  {
    name: "Pro",
    price: "Planned",
    cadence: "",
    pitch: "Join the pilot list for cloud and multi-device evaluation.",
    featured: true,
    features: [
      "Everything in Free",
      "Planned cloud-vault pilots",
      "Planned multi-device evaluation",
      "Fixed-membership team-vault pilots",
      "Commercial terms set before each pilot",
    ],
    cta: {
      label: "Join the Pro pilot list",
      href: "mailto:mason@ashlr.ai?subject=Phantom%20Pro%20pilot",
    },
  },
  {
    name: "Enterprise",
    price: "Custom",
    cadence: "",
    pitch: "Scope a bounded evaluation before any commercial rollout.",
    featured: false,
    features: [
      "Written pilot scope and acceptance criteria",
      "Evaluate local audit tooling",
      "SSO/SAML not shipped",
      "On-prem deployment option (planned)",
      "Support scope by written agreement",
    ],
    cta: { label: "Talk to us", href: "mailto:mason@ashlr.ai" },
  },
];

export default function PricingPage() {
  return (
    <>
      <Nav />
      <main>
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
              Open source today · commercial pilots by agreement
            </span>

            <h1 className="mt-7 font-extrabold tracking-[-0.04em] leading-[1.04] text-white text-[clamp(2.2rem,5.4vw,3.8rem)]">
              Free for you.
              <br />
              <span className="bg-gradient-to-br from-blue-b via-blue to-blue-d bg-clip-text text-transparent">
                Cloud pilots by agreement.
              </span>
            </h1>

            <p className="mt-6 mx-auto max-w-[600px] text-[0.98rem] sm:text-[1.04rem] leading-[1.65] text-t2">
              The CLI, vault, proxy, and MCP server are open source forever.
              Pro billing and cloud entitlements are not commissioned; contact
              us to scope a bounded pilot.
            </p>
          </div>
        </header>

        {/* Tier cards */}
        <section className="pb-20 sm:pb-28">
          <div className="mx-auto max-w-[1100px] px-7">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              {TIERS.map((t) => (
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
                        Pilot list
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
                      onClick={() =>
                        posthog.capture("pricing_cta_clicked", {
                          tier: t.name.toLowerCase(),
                        })
                      }
                      className="mt-6 inline-flex items-center justify-center min-h-[44px] rounded-lg border border-border-l px-4 py-2.5 text-[0.88rem] font-semibold text-t1 no-underline transition-colors duration-200 hover:border-t3"
                    >
                      {t.cta.label}
                    </a>
                  </article>
              ))}
            </div>

            <p className="mt-10 text-center text-[0.82rem] text-t3 max-w-[680px] mx-auto leading-[1.7]">
              All plans include the open-source CLI, the local proxy, the MCP
              server, and the local vault. Cloud plans, billing, and hosted
              entitlements are not commissioned. Any pilot requires written
              scope and acceptance criteria before access is represented as
              available.
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
