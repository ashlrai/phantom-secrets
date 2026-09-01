"use client";

import { useSupabaseQuery } from "@/lib/use-supabase-query";

type UserRow = {
  github_login: string;
  email: string | null;
};

export default function BillingPageClient() {
  const { data: user, error: queryError } = useSupabaseQuery<UserRow>((sb) =>
    sb.from("users").select("github_login, email").single()
  );
  const error = queryError;

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

  return (
    <div className="grid gap-6 max-w-[760px]">
      <section className="rounded-2xl border border-border bg-s1 p-6">
        <p className="text-[0.72rem] font-mono uppercase tracking-[0.1em] text-t3">
          Access status
        </p>
        <div className="mt-2 flex items-baseline gap-3">
          <h2 className="text-[2.2rem] font-extrabold tracking-[-0.04em] text-white leading-none">
            Local
          </h2>
        </div>
        <p className="mt-3 text-[0.85rem] text-t2 leading-[1.65]">
          Local vaults, the proxy, and the MCP server are available today.
          Phantom Cloud and managed billing remain a limited, uncommissioned
          pilot; this dashboard does not collect payment or start a
          subscription.
        </p>

        <a
          href="mailto:mason@ashlr.ai?subject=Phantom%20Cloud%20pilot%20interest"
          className="mt-6 inline-flex min-h-[44px] items-center rounded-lg border border-border-l bg-s2 px-4 py-2 text-[0.88rem] font-semibold text-t1 no-underline transition-colors hover:border-t3"
        >
          Request pilot access
        </a>
      </section>

      <section className="rounded-2xl border border-border bg-s1 p-6">
        <h3 className="text-[0.95rem] font-bold text-t1">Pilot boundary</h3>
        <p className="mt-2 text-[0.85rem] text-t2 leading-[1.65]">
          Pilot interest is reviewed by a person. Requesting access does not
          create a paid account, authorize a charge, or guarantee availability.
        </p>
      </section>
    </div>
  );
}
