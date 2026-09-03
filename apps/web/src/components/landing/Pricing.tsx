import { COMMERCIAL_NON_CLAIMS } from "@/lib/commercial-offerings";
import { OfferingGrid } from "./OfferingGrid";

export function Pricing() {
  return (
    <section id="pricing" className="border-t border-border py-24 sm:py-28">
      <div className="mx-auto max-w-[1100px] px-7">
        <div className="max-w-[640px] mb-12">
          <h2 className="text-[1.8rem] sm:text-[2.4rem] font-extrabold tracking-[-0.035em] leading-[1.08] text-white">
            Open-source core. Commercial help when you need it.
          </h2>
          <p className="mt-4 text-[0.98rem] text-t2 leading-[1.65]">
            Phantom&apos;s local-first core is MIT-licensed. Organizations can
            separately contract for a bounded evaluation, integration work,
            and written support terms without surrendering those open-source
            rights.
          </p>
        </div>

        <OfferingGrid />

        <p className="mt-8 text-center text-[0.78rem] text-t3">
          A commercial agreement buys defined services and commitments—not
          permission already granted by the MIT License. No payment is
          collected here.
        </p>

        <div className="mt-6 rounded-xl border border-border bg-s1/60 p-5">
          <p className="text-[0.72rem] font-mono uppercase tracking-[0.12em] text-t3">
            Not represented as available
          </p>
          <p className="mt-2 text-[0.82rem] leading-[1.65] text-t2">
            {COMMERCIAL_NON_CLAIMS.join(" · ")}
          </p>
        </div>
      </div>
    </section>
  );
}
