"use client";

import { useState, useEffect } from "react";
import { posthog } from "@/lib/posthog";

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
        // Not authenticated — redirect to login flow
        window.location.href = "/device";
      }
    } catch {
      setLoading(false);
    }
  };

  return (
    <main className="min-h-screen flex flex-col items-center p-8 pt-24">
      {/* Nav */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-[#050508]/80 backdrop-blur-xl border-b border-[#1a1a2c]/50">
        <div className="max-w-[1060px] mx-auto px-7 h-14 flex items-center justify-between">
          <a href="/" className="flex items-center gap-2 text-[#f5f5f7] no-underline">
            <img src="/favicon.svg" alt="Phantom" className="w-[22px] h-[22px]" />
            <span className="font-bold text-[.95rem]">Phantom</span>
          </a>
          <div className="flex gap-5 items-center">
            <a href="/" className="text-[#a1a1b5] text-sm font-medium hover:text-[#f5f5f7] no-underline">Home</a>
            <a href="https://github.com/ashlrai/phantom-secrets" className="text-[#a1a1b5] text-sm font-medium hover:text-[#f5f5f7] no-underline">GitHub</a>
          </div>
        </div>
      </nav>

      {success && (
        <div className="mb-8 px-6 py-4 bg-green-500/10 border border-green-500/20 rounded-lg text-green-400 font-semibold text-center">
          Welcome to Phantom Pro! Your subscription is active.
        </div>
      )}

      <h1 className="text-4xl font-black tracking-tight mb-4">Pricing</h1>
      <p className="text-[#a1a1b5] mb-12">
        Start free. Upgrade when you need cloud sync.
      </p>

      <div className="grid md:grid-cols-3 gap-6 max-w-4xl w-full">
        {/* Free */}
        <div className="border border-[#1a1a2c] rounded-xl p-6">
          <h2 className="text-xl font-bold mb-2">Free</h2>
          <p className="text-3xl font-black mb-4">
            $0<span className="text-sm font-normal text-[#65657a]">/mo</span>
          </p>
          <ul className="space-y-2 text-sm text-[#a1a1b5] mb-6">
            <li>Local vault (keychain or encrypted file)</li>
            <li>Proxy with streaming support</li>
            <li>MCP server for Claude Code</li>
            <li>Unlimited local secrets</li>
            <li>1 cloud vault (up to 10 secrets)</li>
            <li>Vercel &amp; Railway sync</li>
          </ul>
          <a
            href="https://github.com/ashlrai/phantom-secrets"
            className="block text-center py-2.5 border border-[#1a1a2c] rounded-lg hover:border-[#333] transition-colors font-semibold"
          >
            Install Free
          </a>
        </div>

        {/* Pro */}
        <div className="border-2 border-blue-600 rounded-xl p-6 relative">
          <span className="absolute -top-3 left-1/2 -translate-x-1/2 bg-blue-600 text-xs font-bold px-3 py-1 rounded-full">
            POPULAR
          </span>
          <h2 className="text-xl font-bold mb-2">Pro</h2>
          <p className="text-3xl font-black mb-4">
            $8<span className="text-sm font-normal text-[#65657a]">/mo</span>
          </p>
          <ul className="space-y-2 text-sm text-[#a1a1b5] mb-6">
            <li>Everything in Free</li>
            <li>Unlimited cloud vaults</li>
            <li>Multi-device sync</li>
            <li>Vault backup &amp; restore</li>
            <li>Priority support</li>
          </ul>
          <button
            onClick={handleSubscribe}
            disabled={loading}
            className="w-full py-2.5 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 disabled:cursor-wait rounded-lg font-semibold transition-colors"
          >
            {loading ? "Redirecting..." : "Subscribe — $8/mo"}
          </button>
        </div>

        {/* Enterprise */}
        <div className="border border-[#1a1a2c] rounded-xl p-6">
          <h2 className="text-xl font-bold mb-2">Enterprise</h2>
          <p className="text-3xl font-black mb-4">Custom</p>
          <ul className="space-y-2 text-sm text-[#a1a1b5] mb-6">
            <li>Everything in Pro</li>
            <li>Team vaults &amp; sharing</li>
            <li>Audit log</li>
            <li>SSO/SAML</li>
            <li>Dedicated support</li>
          </ul>
          <a
            href="mailto:mason@ashlr.ai"
            className="block text-center py-2.5 border border-[#1a1a2c] rounded-lg hover:border-[#333] transition-colors font-semibold"
          >
            Contact Us
          </a>
        </div>
      </div>

      <p className="text-[#65657a] text-sm mt-12 text-center max-w-lg">
        All plans include the open-source CLI. Cloud features require a Phantom account.
        Vaults are end-to-end encrypted &mdash; we never see your secrets.
      </p>
    </main>
  );
}
