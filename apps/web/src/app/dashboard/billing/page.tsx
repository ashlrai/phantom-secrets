"use client";

import { useState } from "react";
import { getBrowserClient } from "@/lib/supabase-browser";
import { useSupabaseQuery } from "@/lib/use-supabase-query";

type UserRow = {
  github_login: string;
  email: string | null;
  plan: string;
  plan_expires_at: string | null;
  stripe_customer_id: string | null;
};

export default function BillingPage() {
  const { data: user, error: queryError } = useSupabaseQuery<UserRow>((sb) =>
    sb
      .from("users")
      .select("github_login, email, plan, plan_expires_at, stripe_customer_id")
      .single()
  );
  const [loadingPortal, setLoadingPortal] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const error = actionError ?? queryError;

  const openPortal = async () => {
    const supabase = getBrowserClient();
    const {
      data: { session },
    } = await supabase.auth.getSession();
    if (!session) {
      setActionError("Not signed in.");
      return;
    }
    setLoadingPortal(true);
    setActionError(null);
    try {
      const resp = await fetch("/api/v1/billing/portal", {
        method: "POST",
        headers: { Authorization: `Bearer ${session.access_token}` },
      });
      if (!resp.ok) {
        setActionError("Could not open Stripe portal. Email mason@ashlr.ai if this persists.");
        setLoadingPortal(false);
        return;
      }
      const data = (await resp.json()) as { url?: string };
      if (data.url) {
        window.location.href = data.url;
      } else {
        setActionError("Portal returned no URL.");
        setLoadingPortal(false);
      }
    } catch {
      setActionError("Network error reaching billing portal.");
      setLoadingPortal(false);
    }
  };

  if (error) {
    return (
      <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-5 py-4 text-[0.92rem] text-red-300">
        {error}
      </div>
    );
  }

  if (!user) {
    return <div className="text-[0.9rem] text-t3">Loading billing…</div>;
  }

  const isPro = user.plan === "pro";

  return (
    <div className="grid gap-6 max-w-[760px]">
      <section className="rounded-2xl border border-border bg-s1 p-6">
        <p className="text-[0.72rem] font-mono uppercase tracking-[0.1em] text-t3">
          Current plan
        </p>
        <div className="mt-2 flex items-baseline gap-3">
          <h2 className="text-[2.2rem] font-extrabold tracking-[-0.04em] text-white leading-none">
            {isPro ? "Pro" : "Free"}
          </h2>
          <span className="text-[0.95rem] text-t3">
            {isPro ? "$8 / month" : "$0"}
          </span>
        </div>
        {isPro && user.plan_expires_at && (
          <p className="mt-3 text-[0.85rem] text-t2">
            Renews on {new Date(user.plan_expires_at).toLocaleDateString()}.
          </p>
        )}
        {!isPro && (
          <p className="mt-3 text-[0.85rem] text-t2">
            Local vaults, the proxy, and the MCP server are free forever. Pro
            unlocks unlimited cloud vaults, multi-device sync, and priority
            support.
          </p>
        )}

        <div className="mt-6">
          {isPro ? (
            <button
              type="button"
              onClick={openPortal}
              disabled={loadingPortal}
              className="inline-flex min-h-[44px] items-center rounded-lg border border-border-l bg-s2 px-4 py-2 text-[0.88rem] font-semibold text-t1 transition-colors hover:border-t3 disabled:opacity-60 disabled:cursor-wait"
            >
              {loadingPortal ? "Opening Stripe…" : "Manage subscription in Stripe"}
            </button>
          ) : (
            <a
              href="/pricing"
              className="inline-flex min-h-[44px] items-center rounded-lg bg-blue px-4 py-2 text-[0.88rem] font-semibold text-white no-underline transition-all hover:bg-blue-d hover:-translate-y-px hover:shadow-[0_4px_24px_rgba(59,130,246,0.32)]"
            >
              Upgrade to Pro — $8 / mo
            </a>
          )}
        </div>
      </section>

      <section className="rounded-2xl border border-border bg-s1 p-6">
        <h3 className="text-[0.95rem] font-bold text-t1">Receipt + invoices</h3>
        <p className="mt-2 text-[0.85rem] text-t2 leading-[1.65]">
          Past invoices, payment methods, and the option to cancel live in
          Stripe&apos;s portal. We never store your card.
        </p>
      </section>
    </div>
  );
}
