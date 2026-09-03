"use client";

import Image from "next/image";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { posthog } from "@/lib/posthog";
import { Github } from "./Icons";

const navigation = [
  { label: "How it works", section: "how" },
  { label: "Features", section: "features" },
  { label: "Pricing", href: "/pricing" },
  { label: "Enterprise", href: "/enterprise" },
  { label: "Security", href: "/security" },
] as const;

const navLinkClass =
  "rounded-md px-2 py-2 text-[0.84rem] font-medium text-t2 no-underline transition-colors hover:text-t1 focus-visible:text-t1";

function homeSectionHref(pathname: string, section: string) {
  return pathname === "/" ? `#${section}` : `/#${section}`;
}

function isCurrentPath(pathname: string, href: string) {
  return pathname === href || pathname.startsWith(`${href}/`);
}

export function Nav() {
  const pathname = usePathname();
  const [scrolled, setScrolled] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 8);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  useEffect(() => {
    if (!menuOpen) return;

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setMenuOpen(false);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [menuOpen]);

  const installHref = homeSectionHref(pathname, "install");

  return (
    <nav
      aria-label="Primary navigation"
      className={[
        "sticky top-0 z-50 w-full",
        "backdrop-blur-xl supports-[backdrop-filter]:bg-bg/70",
        "transition-[border-color,background-color] duration-300",
        scrolled || menuOpen
          ? "border-b border-border/60 bg-bg/95"
          : "border-b border-transparent bg-bg/65",
      ].join(" ")}
    >
      {/* Dashboard main targets are owned by the authenticated application shell. */}
      {!pathname.startsWith("/dashboard") && (
        <a
          href="#main-content"
          className="fixed left-4 top-4 z-[100] -translate-y-24 rounded-md bg-white px-4 py-2 text-sm font-semibold text-bg shadow-xl transition-transform focus:translate-y-0"
        >
          Skip to main content
        </a>
      )}
      <div className="mx-auto flex h-16 max-w-[1200px] items-center justify-between gap-4 px-5 sm:px-7">
        <Link
          href="/"
          aria-label="Phantom home"
          className="flex shrink-0 items-center gap-2.5 text-t1 no-underline"
          onClick={() => setMenuOpen(false)}
        >
          <Image
            src="/favicon.svg"
            alt=""
            width={22}
            height={22}
            priority
          />
          <span className="font-bold text-[0.95rem] tracking-tight">Phantom</span>
        </Link>

        <div className="hidden items-center gap-1 lg:flex">
          {navigation.map((item) => {
            const href = "section" in item
              ? homeSectionHref(pathname, item.section)
              : item.href;
            const active = "href" in item && isCurrentPath(pathname, item.href);

            return (
              <Link
                key={item.label}
                href={href}
                aria-current={active ? "page" : undefined}
                className={`${navLinkClass} ${active ? "text-t1" : ""}`}
              >
                {item.label}
              </Link>
            );
          })}
          <a
            href="https://github.com/ashlrai/phantom-secrets/blob/main/docs/getting-started.md"
            className={navLinkClass}
          >
            Docs
          </a>
        </div>

        <div className="flex items-center gap-2 sm:gap-3">
          <a
            href="https://github.com/ashlrai/phantom-secrets"
            aria-label="View Phantom on GitHub"
            className="hidden h-10 w-10 items-center justify-center rounded-md border border-border bg-s2 text-t2 transition-colors hover:border-blue hover:text-t1 sm:inline-flex"
          >
            <Github aria-hidden className="h-3.5 w-3.5" />
          </a>

          <Link
            href={installHref}
            onClick={() => {
              setMenuOpen(false);
              posthog.capture("nav_get_started_clicked");
            }}
            className="inline-flex min-h-10 items-center rounded-md bg-blue px-3.5 py-2 text-[0.82rem] font-semibold text-white no-underline transition-all duration-200 hover:-translate-y-px hover:bg-blue-d hover:shadow-[0_4px_18px_rgba(59,130,246,0.4)] sm:px-4"
          >
            Get started
          </Link>

          <button
            type="button"
            aria-label={menuOpen ? "Close navigation menu" : "Open navigation menu"}
            aria-expanded={menuOpen}
            aria-controls="mobile-navigation"
            onClick={() => setMenuOpen((open) => !open)}
            className="inline-flex h-10 w-10 items-center justify-center rounded-md border border-border bg-s2 text-t1 transition-colors hover:border-blue lg:hidden"
          >
            <svg
              aria-hidden="true"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.8"
              strokeLinecap="round"
              className="h-5 w-5"
            >
              {menuOpen ? (
                <path d="M6 6l12 12M18 6 6 18" />
              ) : (
                <path d="M4 7h16M4 12h16M4 17h16" />
              )}
            </svg>
          </button>
        </div>
      </div>

      <div
        id="mobile-navigation"
        hidden={!menuOpen}
        className="border-t border-border/70 bg-bg/98 px-5 py-4 shadow-2xl lg:hidden sm:px-7"
      >
        <div className="mx-auto grid max-w-[1200px] gap-1">
          {navigation.map((item) => {
            const href = "section" in item
              ? homeSectionHref(pathname, item.section)
              : item.href;
            const active = "href" in item && isCurrentPath(pathname, item.href);

            return (
              <Link
                key={item.label}
                href={href}
                aria-current={active ? "page" : undefined}
                onClick={() => setMenuOpen(false)}
                className={`rounded-lg px-3 py-3 text-[0.92rem] font-medium no-underline transition-colors hover:bg-s2 hover:text-t1 ${
                  active ? "bg-s2 text-t1" : "text-t2"
                }`}
              >
                {item.label}
              </Link>
            );
          })}
          <a
            href="https://github.com/ashlrai/phantom-secrets/blob/main/docs/getting-started.md"
            onClick={() => setMenuOpen(false)}
            className="rounded-lg px-3 py-3 text-[0.92rem] font-medium text-t2 no-underline transition-colors hover:bg-s2 hover:text-t1"
          >
            Documentation
          </a>
          <a
            href="https://github.com/ashlrai/phantom-secrets"
            onClick={() => setMenuOpen(false)}
            className="flex items-center gap-2 rounded-lg px-3 py-3 text-[0.92rem] font-medium text-t2 no-underline transition-colors hover:bg-s2 hover:text-t1 sm:hidden"
          >
            <Github aria-hidden className="h-4 w-4" />
            GitHub
          </a>
        </div>
      </div>
    </nav>
  );
}
