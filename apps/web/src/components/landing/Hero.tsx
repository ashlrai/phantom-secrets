"use client";

import { posthog } from "@/lib/posthog";
import { CopyButton } from "./CopyButton";
import { KEY_ENTRIES } from "./BrandLogos";
import { Github } from "./Icons";

export function Hero() {
  return (
    <header className="relative pt-14 pb-20 sm:pt-20 sm:pb-28 overflow-hidden">
      {/* Soft halo behind the headline */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-x-0 top-0 h-[680px] -z-10 opacity-60"
        style={{
          background:
            "radial-gradient(ellipse 60% 60% at 50% 0%, rgba(59,130,246,0.18) 0%, transparent 70%)",
        }}
      />

      <div className="mx-auto max-w-[940px] px-7 text-center">
        <span className="inline-flex items-center gap-2 rounded-full border border-border bg-s1/80 px-3 py-1 text-[0.72rem] font-medium text-t2 backdrop-blur-md">
          <span className="relative flex h-1.5 w-1.5">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-blue/60 opacity-75" />
            <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-blue" />
          </span>
          For Claude Code · Cursor · Windsurf · Codex
        </span>

        <h1 className="mt-7 font-extrabold tracking-[-0.045em] leading-[1.0] text-white text-[clamp(2.6rem,6.4vw,4.6rem)]">
          Delegate everything to AI.
          <br />
          <span className="bg-gradient-to-br from-blue-b via-blue to-blue-d bg-clip-text text-transparent">
            Without sharing a single key.
          </span>
        </h1>

        <p className="mt-6 mx-auto max-w-[600px] text-[0.98rem] sm:text-[1.04rem] leading-[1.65] text-t2">
          Phantom hands every AI tool a worthless{" "}
          <code className="font-mono text-blue-b text-[0.92em]">phm_</code>{" "}
          token. The local proxy injects the real key at the network layer.
          Full access. Zero exposure.
        </p>

        <div className="mt-8 mx-auto w-full max-w-[460px]">
          <CopyButton text="npx phantom-secrets init" />
        </div>

        <div className="mt-5 flex flex-wrap justify-center gap-2.5">
          <a
            href="#install"
            onClick={() => posthog.capture("hero_get_started_clicked")}
            className="inline-flex items-center gap-2 rounded-lg bg-blue px-5 py-2.5 text-[0.9rem] font-semibold text-white no-underline transition-all duration-200 hover:bg-blue-d hover:-translate-y-px hover:shadow-[0_4px_24px_rgba(59,130,246,0.32)]"
          >
            Get started
          </a>
          <a
            href="https://github.com/ashlrai/phantom-secrets"
            className="inline-flex items-center gap-2 rounded-lg border border-border-l bg-s1 px-5 py-2.5 text-[0.9rem] font-semibold text-t1 no-underline transition-colors duration-200 hover:border-t3"
          >
            <Github className="h-3.5 w-3.5" />
            View on GitHub
          </a>
        </div>
      </div>

      {/* Two-row counter-rotating marquee of API key cards */}
      <KeyWall />
    </header>
  );
}

function KeyWall() {
  // Split entries into two rows so opposing motion creates visual depth.
  // Even-indexed entries → top row (scrolls left), odd → bottom (scrolls right).
  const rowA = KEY_ENTRIES.filter((_, i) => i % 2 === 0);
  const rowB = KEY_ENTRIES.filter((_, i) => i % 2 === 1);

  return (
    <section
      aria-label="Phantom protects API keys for every popular service"
      className="relative mt-16 sm:mt-20"
    >
      <p className="mx-auto max-w-[940px] px-7 text-center text-[0.78rem] font-medium uppercase tracking-[0.18em] text-t3 mb-8">
        Replaces real keys for {KEY_ENTRIES.length}+ services and counting
      </p>

      <div className="relative space-y-3 sm:space-y-4">
        {/* Edge fades — sit above both marquee rows */}
        <div
          aria-hidden
          className="pointer-events-none absolute inset-y-0 left-0 z-10 w-32 sm:w-48 bg-gradient-to-r from-bg via-bg/85 to-transparent"
        />
        <div
          aria-hidden
          className="pointer-events-none absolute inset-y-0 right-0 z-10 w-32 sm:w-48 bg-gradient-to-l from-bg via-bg/85 to-transparent"
        />

        <Marquee items={rowA} duration={62} direction="left" />
        <Marquee items={rowB} duration={74} direction="right" />
      </div>
    </section>
  );
}

function Marquee({
  items,
  duration,
  direction,
}: {
  items: typeof KEY_ENTRIES;
  duration: number;
  direction: "left" | "right";
}) {
  // Duplicate so translateX(-50% / +50%) creates a seamless loop
  const track = [...items, ...items];
  const animationName = direction === "left" ? "marqueeLeft" : "marqueeRight";

  return (
    <div className="overflow-hidden marquee-pause-on-hover">
      <div
        className="flex gap-3 sm:gap-4 w-max marquee-track"
        style={{
          animation: `${animationName} ${duration}s linear infinite`,
        }}
      >
        {track.map((k, i) => (
          <KeyCard key={`${k.name}-${i}`} item={k} />
        ))}
      </div>
    </div>
  );
}

function KeyCard({ item }: { item: typeof KEY_ENTRIES[number] }) {
  const { Logo, name, env, token, color } = item;
  // CSS variable so we can use the dynamic brand color in className-driven
  // hover states (Tailwind arbitrary values can read CSS vars).
  const brandStyle = { "--brand": color } as React.CSSProperties;

  return (
    <article
      style={brandStyle}
      className="group relative flex w-[280px] sm:w-[310px] shrink-0 items-center gap-3.5 rounded-xl border border-border bg-s1 px-4 py-3.5 transition-all duration-200 hover:-translate-y-0.5 hover:border-[color:var(--brand)] hover:shadow-[0_4px_22px_-8px_var(--brand)] overflow-hidden"
    >
      {/* Brand-color accent stripe down the left edge */}
      <span
        aria-hidden
        className="pointer-events-none absolute -left-px top-0 bottom-0 w-[3px] opacity-0 transition-opacity duration-200 group-hover:opacity-100"
        style={{ backgroundColor: color }}
      />

      <div
        className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-border bg-s2 text-t2 transition-colors duration-200 group-hover:[color:var(--brand)] group-hover:bg-[color:var(--brand)]/10 group-hover:border-[color:var(--brand)]/40"
      >
        <Logo className="h-5 w-5" />
      </div>

      <div className="min-w-0 flex-1">
        <div className="flex items-baseline justify-between gap-2">
          <span className="text-[0.86rem] font-semibold text-t1 truncate transition-colors duration-200 group-hover:[color:var(--brand)]">
            {name}
          </span>
          <span
            className="inline-flex items-center gap-1 text-[0.66rem] font-mono uppercase tracking-[0.06em] text-green/85 shrink-0"
          >
            <span
              aria-hidden
              className="inline-block h-1.5 w-1.5 rounded-full bg-green animate-pulse"
            />
            safe
          </span>
        </div>
        <div className="mt-1 font-mono text-[0.72rem] leading-tight truncate">
          <span className="text-t3">{env}=</span>
          <span className="text-blue-b">{token}</span>
        </div>
      </div>
    </article>
  );
}
