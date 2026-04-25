"use client";

import Image from "next/image";
import { useEffect, useState } from "react";
import { Github } from "./Icons";

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
      <div className="mx-auto max-w-[1080px] px-7 h-14 flex items-center justify-between">
        <a href="/" className="flex items-center gap-2.5 text-t1 no-underline">
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
          <a
            href="#how"
            className="hidden sm:inline text-t2 hover:text-t1 transition-colors text-[0.85rem] font-medium no-underline"
          >
            How it works
          </a>
          <a
            href="#features"
            className="hidden sm:inline text-t2 hover:text-t1 transition-colors text-[0.85rem] font-medium no-underline"
          >
            Features
          </a>
          <a
            href="/pricing"
            className="hidden sm:inline text-t2 hover:text-t1 transition-colors text-[0.85rem] font-medium no-underline"
          >
            Pricing
          </a>
          <a
            href="https://github.com/ashlrai/phantom-secrets/blob/main/docs/getting-started.md"
            className="hidden sm:inline text-t2 hover:text-t1 transition-colors text-[0.85rem] font-medium no-underline"
          >
            Docs
          </a>
          <a
            href="https://github.com/ashlrai/phantom-secrets"
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 bg-s2 border border-border hover:border-blue rounded-md text-[0.82rem] font-semibold text-t1 no-underline transition-colors"
          >
            <Github className="w-[15px] h-[15px]" />
            GitHub
          </a>
        </div>
      </div>
    </nav>
  );
}
