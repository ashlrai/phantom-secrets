"use client";

import { useState, useEffect } from "react";
import { posthog } from "@/lib/posthog";
import { Nav } from "@/components/landing/Nav";
import { SiteFooter } from "@/components/landing/SiteFooter";
import { Check } from "@/components/landing/Icons";
import { FAQ } from "@/components/landing/FAQ";
import { Comparison } from "@/components/landing/Comparison";

const TIERS = [
  {
    name: "Free",
    price: "$0",
    cadence: "/mo",
    pitch: "Local-first. Open source. Forever.",
    features: [
      "Local vault (OS keychain or encrypted file)",
      "Proxy with full streaming support",
      "MCP server for every editor",
      "27 CLI commands · 17 MCP tools",
      "Unlimited local secrets",
      "1 cloud vault (up to 10 secrets)",
      "Vercel & Railway sync",
    ],
    cta: { label: "Install free", kind: "link", href: "https://github.com/ashlrai/phantom-secrets" },
  },
  {
    name: "Pro",
    price: "$8",
    cadence: "/mo",
    pitch: "Cloud sync, multi-device, full backup.",
    featured: true,
    features: [
      "Everything in Free",
      "Unlimited cloud vaults",
      "Multi-device sync (E2E encrypted)",
      "Vault backup & restore",
      "Pre-commit secret scanning",
      "Priority support",
    ],
    cta: { label: "Start with Pro", kind: "checkout" },
  },
  {
    name: "Enterprise",
    price: "Custom",
    cadence: "",
    pitch: "Teams, audit, SSO, dedicated support.",
    features: [
      "Everything in Pro",
      "Team vaults & shared secrets",
      "Audit log + SSO/SAML",
      "Centralised secret rotation",
      "On-prem deployment option",
      "Dedicated support",
    ],
    cta: { label: "Talk to sales", kind: "link", href: "mailto:mason@ashlr.ai" },
  },
] as const;

export default function PricingPage() {
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get("success") === "true") {
      setSuccess(true);
      window.history.replaceState({}, "", "/pricing");
    }
  }, []);

  const handleSubscribe = async () => {
    setLoading(true);
    posthog.capture("subscribe_clicked", { plan: "pro" });
    try {
      const resp = await fetch("/api/v1/billing/checkout", { method: "POST" });
      const data = await resp.json();
      if (data.url) {
        window.location.href = data.url;
      } else {
        window.location.href = "/device";
      }
    } catch {
      setLoading(false);
    }
  };

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
              Pricing · transparent · cancel any time
            </span>

            <h1 className="mt-7 font-extrabold tracking-[-0.04em] leading-[1.04] text-white text-[clamp(2.2rem,5.4vw,3.8rem)]">
              Free for you.
              <br />
              <span className="bg-gradient-to-br from-blue-b via-blue to-blue-d bg-clip-text text-transparent">
                Eight bucks for your team.
              </span>
            </h1>

            <p className="mt-6 mx-auto max-w-[600px] text-[0.98rem] sm:text-[1.04rem] leading-[1.65] text-t2">
              The CLI, vault, proxy, and MCP server are open source forever.
              Cloud sync and multi-device cost what a coffee costs.
            </p>
          </div>
        </header>

        {success && (
          <div className="mx-auto max-w-[640px] px-7 mb-8">
            <div className="rounded-xl border border-green/30 bg-green/10 px-5 py-4 text-[0.92rem] font-medium text-green flex items-center gap-3">
              <span
                aria-hidden
                className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-green/15"
              >
                <Check className="h-4 w-4 text-green" strokeWidth={2.6} />
              </span>
              Welcome to Phantom Pro — your subscription is active.
            </div>
          </div>
        )}

        {/* Tier cards */}
        <section className="pb-20 sm:pb-28">
          <div className="mx-auto max-w-[1100px] px-7">
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
                        Most popular
                      </span>
                    )}

                    <div className={`flex items-baseline justify-between ${featured ? "mt-3" : ""}`}>
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

                    {t.cta.kind === "checkout" ? (
                      <button
                        type="button"
                        onClick={handleSubscribe}
                        disabled={loading}
                        className="mt-6 inline-flex items-center justify-center min-h-[44px] rounded-lg bg-blue px-4 py-2.5 text-[0.88rem] font-semibold text-white transition-all duration-200 hover:bg-blue-d hover:-translate-y-px hover:shadow-[0_4px_24px_rgba(59,130,246,0.32)] disabled:bg-blue/60 disabled:cursor-wait disabled:hover:translate-y-0 disabled:hover:shadow-none"
                      >
                        {loading ? "Redirecting…" : `${t.cta.label} — $8/mo`}
                      </button>
                    ) : (
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
                    )}
                  </article>
                );
              })}
            </div>

            <p className="mt-10 text-center text-[0.82rem] text-t3 max-w-[680px] mx-auto leading-[1.7]">
              All plans include the open-source CLI, the local proxy, the MCP
              server, and the local vault. Cloud features require a Phantom
              account. Vaults are end-to-end encrypted — we never see your
              secrets, even on Pro or Enterprise.
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
