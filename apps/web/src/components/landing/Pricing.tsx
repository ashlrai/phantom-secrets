"use client";

import { posthog } from "@/lib/posthog";
import { Check } from "./Icons";

const TIERS = [
  {
    name: "Free",
    price: "$0",
    cadence: "/mo",
    pitch: "Local-first. Open source. Forever.",
    features: [
      "Local vault (OS keychain or encrypted file)",
      "Proxy with full streaming support",
      "MCP server for supported clients",
      "Unlimited local secrets",
    ],
    cta: { label: "Install free", href: "#install", primary: false },
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
      primary: true,
    },
  },
  {
    name: "Enterprise",
    price: "Custom",
    cadence: "",
    pitch: "Scope a bounded evaluation before any commercial rollout.",
    features: [
      "Written pilot scope and acceptance criteria",
      "Evaluate local audit tooling",
      "SSO/SAML not shipped",
      "Support scope by written agreement",
    ],
    cta: { label: "Talk to us", href: "mailto:mason@ashlr.ai", primary: false },
  },
];

export function Pricing() {
  return (
    <section id="pricing" className="border-t border-border py-24 sm:py-28">
      <div className="mx-auto max-w-[1100px] px-7">
        <div className="max-w-[640px] mb-12">
          <h2 className="text-[1.8rem] sm:text-[2.4rem] font-extrabold tracking-[-0.035em] leading-[1.08] text-white">
            Open source today. Cloud pilots by agreement.
          </h2>
          <p className="mt-4 text-[0.98rem] text-t2 leading-[1.65]">
            The CLI, vault, proxy, and MCP server are open source forever.
            Pro billing and cloud entitlements are not commissioned; contact us
            to scope a bounded pilot.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {TIERS.map((t) => {
            const featured = "featured" in t && t.featured;
            return (
              <article
                key={t.name}
                className={
                  "relative rounded-2xl border bg-s1 p-7 flex flex-col " +
                  (featured
                    ? "border-blue-d/70 shadow-[0_0_60px_-20px_rgba(59,130,246,0.45)]"
                    : "border-border")
                }
              >
                {featured && (
                  <span className="absolute -top-2.5 left-7 rounded-full border border-blue-d/40 bg-blue px-2.5 py-0.5 text-[0.7rem] font-bold uppercase tracking-[0.12em] text-white">
                    Pilot list
                  </span>
                )}

                <div className={`flex items-baseline justify-between ${featured ? "mt-3" : ""}`}>
                  <h3 className="text-[1.05rem] font-bold text-t1">{t.name}</h3>
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
                  className={
                    "mt-6 inline-flex items-center justify-center min-h-[44px] rounded-lg px-4 py-2.5 text-[0.88rem] font-semibold no-underline transition-all duration-200 " +
                    (t.cta.primary
                      ? "bg-blue text-white hover:bg-blue-d hover:-translate-y-px hover:shadow-[0_4px_24px_rgba(59,130,246,0.32)]"
                      : "border border-border-l text-t1 hover:border-t3")
                  }
                >
                  {t.cta.label}
                </a>
              </article>
            );
          })}
        </div>

        <p className="mt-8 text-center text-[0.78rem] text-t3">
          No payment is collected from this page. Pilot access requires written
          scope and commissioning.
        </p>
      </div>
    </section>
  );
}
