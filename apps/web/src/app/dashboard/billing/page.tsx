import { isHostedServiceCommissioned } from "@/lib/commissioning";
import BillingPageClient from "./billing-client";

export default function BillingPage() {
  if (!isHostedServiceCommissioned("billing")) {
    return (
      <div className="grid gap-6 max-w-[760px]">
        <section className="rounded-2xl border border-border bg-s1 p-6">
          <p className="text-[0.72rem] font-mono uppercase tracking-[0.1em] text-t3">
            Access status
          </p>
          <h2 className="mt-2 text-[2.2rem] font-extrabold tracking-[-0.04em] text-white leading-none">
            Local
          </h2>
          <p className="mt-3 text-[0.85rem] text-t2 leading-[1.65]">
            Managed billing is not commissioned on this deployment. This page
            does not collect payment or start a subscription, and it will not
            query billing records or create a Stripe session while the
            server-only billing gate is closed.
          </p>
          <a
            href="mailto:mason@ashlr.ai?subject=Phantom%20Cloud%20pilot%20interest"
            className="mt-6 inline-flex min-h-[44px] items-center rounded-lg border border-border-l bg-s2 px-4 py-2 text-[0.88rem] font-semibold text-t1 no-underline transition-colors hover:border-t3"
          >
            Request pilot access
          </a>
        </section>
      </div>
    );
  }

  return <BillingPageClient />;
}
