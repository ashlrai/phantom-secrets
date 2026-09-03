"use client";

import { capturePostHog } from "@/lib/posthog";

type CommercialCtaProps = {
  featured: boolean;
  href: string;
  label: string;
  offeringId: string;
};

export function CommercialCta({
  featured,
  href,
  label,
  offeringId,
}: CommercialCtaProps) {
  return (
    <a
      href={href}
      onClick={() => void capturePostHog("pricing_cta_clicked", { tier: offeringId })}
      className={
        "mt-6 inline-flex min-h-[44px] items-center justify-center rounded-lg px-4 py-2.5 text-[0.88rem] font-semibold no-underline transition-all duration-200 " +
        (featured
          ? "bg-blue-action text-white hover:-translate-y-px hover:bg-blue-action-d hover:shadow-[0_4px_24px_rgba(59,130,246,0.32)]"
          : "border border-border-l text-t1 hover:border-t3")
      }
    >
      {label}
    </a>
  );
}
