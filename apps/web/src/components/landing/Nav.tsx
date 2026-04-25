"use client";

import Image from "next/image";
import { useEffect, useState } from "react";
import { posthog } from "@/lib/posthog";
import { Github } from "./Icons";

const navLinkClass =
  "hidden md:inline text-t2 hover:text-t1 transition-colors text-[0.85rem] font-medium no-underline";

export function Nav() {
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 8);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <nav
      className={[
        "sticky top-0 z-50 w-full",
        "backdrop-blur-xl supports-[backdrop-filter]:bg-bg/70",
        "transition-[border-color,background-color] duration-300",
        scrolled
          ? "border-b border-border/60 bg-bg/85"
          : "border-b border-transparent bg-bg/50",
      ].join(" ")}
    >
      <div className="mx-auto max-w-[1200px] px-7 h-14 flex items-center justify-between">
        <a
          href="/"
          className="flex items-center gap-2.5 text-t1 no-underline shrink-0"
        >
          <Image
            src="/favicon.svg"
            alt="Phantom"
            width={22}
            height={22}
            priority
          />
          <span className="font-bold text-[0.95rem] tracking-tight">Phantom</span>
        </a>

        <div className="flex items-center gap-5">
          <a href="#how" className={navLinkClass}>
            How it works
          </a>
          <a href="#features" className={navLinkClass}>
            Features
          </a>
          <a href="#pricing" className={navLinkClass}>
            Pricing
          </a>
          <a
            href="https://github.com/ashlrai/phantom-secrets/blob/main/docs/getting-started.md"
            className={navLinkClass}
          >
            Docs
          </a>

          {/* GitHub icon-only button */}
          <a
            href="https://github.com/ashlrai/phantom-secrets"
            aria-label="View on GitHub"
            className="inline-flex h-8 w-8 items-center justify-center rounded-md border border-border bg-s2 text-t2 hover:text-t1 hover:border-blue transition-colors"
          >
            <Github className="h-3.5 w-3.5" />
          </a>

          {/* Primary CTA */}
          <a
            href="#install"
            onClick={() => posthog.capture("nav_get_started_clicked")}
            className="inline-flex items-center gap-1.5 rounded-md bg-blue px-3.5 py-1.5 text-[0.82rem] font-semibold text-white no-underline transition-all duration-200 hover:bg-blue-d hover:-translate-y-px hover:shadow-[0_4px_18px_rgba(59,130,246,0.4)]"
          >
            Get started
          </a>
        </div>
      </div>
    </nav>
  );
}
