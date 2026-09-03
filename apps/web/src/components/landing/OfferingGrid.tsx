import { COMMERCIAL_OFFERINGS } from "@/lib/commercial-offerings";
import { Check } from "./Icons";
import { CommercialCta } from "./CommercialCta";

type OfferingGridProps = {
  headingLevel?: "h2" | "h3";
};

export function OfferingGrid({ headingLevel = "h3" }: OfferingGridProps) {
  const Heading = headingLevel;

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
      {COMMERCIAL_OFFERINGS.map((offering) => (
        <article
          key={offering.id}
          className={
            "relative flex flex-col rounded-2xl border bg-s1 p-7 " +
            (offering.featured
              ? "border-blue-d/70 shadow-[0_0_60px_-20px_rgba(59,130,246,0.45)]"
              : "border-border")
          }
        >
          {offering.featured && (
            <span className="absolute -top-2.5 left-7 rounded-full border border-blue-d/40 bg-blue px-2.5 py-0.5 text-[0.7rem] font-bold uppercase tracking-[0.12em] text-white">
              Written scope
            </span>
          )}

          <div className={offering.featured ? "mt-3" : ""}>
            <Heading className="text-[1.05rem] font-bold text-t1">
              {offering.name}
            </Heading>
          </div>

          <div className="mt-3 flex items-baseline gap-1">
            <span className="text-[2.4rem] font-extrabold leading-none tracking-[-0.04em] text-white">
              {offering.price}
            </span>
          </div>

          <p className="mt-3 text-[0.85rem] leading-[1.55] text-t2">
            {offering.pitch}
          </p>

          <ul className="mt-5 flex-1 space-y-2">
            {offering.features.map((feature) => (
              <li
                key={feature}
                className="flex items-start gap-2 text-[0.86rem] text-t2"
              >
                <Check
                  className="mt-[3px] h-3.5 w-3.5 shrink-0 text-blue-b"
                  strokeWidth={2.4}
                />
                <span>{feature}</span>
              </li>
            ))}
          </ul>

          <CommercialCta
            featured={offering.featured}
            href={offering.cta.href}
            label={offering.cta.label}
            offeringId={offering.id}
          />
        </article>
      ))}
    </div>
  );
}
