"use client";

import { useEffect, useRef, useState } from "react";
import { CopyButton } from "./CopyButton";
import { Github } from "./Icons";

export function Hero() {
  const videoRef = useRef<HTMLVideoElement>(null);
  const [hasVideo, setHasVideo] = useState<boolean | null>(null);

  useEffect(() => {
    fetch("/hero/loop.mp4", { method: "HEAD" })
      .then((r) => setHasVideo(r.ok))
      .catch(() => setHasVideo(false));
  }, []);

  useEffect(() => {
    const video = videoRef.current;
    if (!video || !hasVideo) return;
    video.loop = true;
    video.play().catch(() => {});
  }, [hasVideo]);

  return (
    <header className="relative">
      <div className="mx-auto max-w-[1200px] px-7 pt-14 pb-20 sm:pt-20 sm:pb-28">
        {/* Above the fold — text block */}
        <div className="mx-auto max-w-[820px] text-center">
          <span className="inline-flex items-center gap-2 rounded-full border border-border bg-s1/80 px-3 py-1 text-[0.72rem] font-medium text-t2 backdrop-blur-md">
            <span className="relative flex h-1.5 w-1.5">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-blue/60 opacity-75" />
              <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-blue" />
            </span>
            For Claude Code · Cursor · Windsurf · Codex
          </span>

          <h1 className="mt-6 font-extrabold tracking-[-0.045em] leading-[1.02] text-white text-[clamp(2.6rem,6.2vw,4.4rem)]">
            Delegate everything to AI.
            <br />
            <span className="text-t3">Without sharing a single key.</span>
          </h1>

          <p className="mt-5 mx-auto max-w-[600px] text-[0.98rem] sm:text-[1.04rem] leading-[1.65] text-t2">
            Phantom hands AI a worthless{" "}
            <code className="font-mono text-blue-b text-[0.92em]">phm_</code>{" "}
            token and injects the real key at the network layer. Full access.
            Zero exposure.
          </p>

          <div className="mt-8 mx-auto w-full max-w-[460px]">
            <CopyButton text="npx phantom-secrets init" />
          </div>

          <div className="mt-5 flex flex-wrap items-center justify-center gap-x-5 gap-y-2 text-[0.85rem]">
            <a
              href="https://github.com/ashlrai/phantom-secrets"
              className="inline-flex items-center gap-1.5 text-t2 hover:text-t1 transition-colors"
            >
              <Github className="h-3.5 w-3.5" />
              GitHub
            </a>
            <span className="text-t3">·</span>
            <a
              href="#how"
              className="text-t2 hover:text-t1 transition-colors"
            >
              How it works
            </a>
            <span className="text-t3">·</span>
            <a
              href="#pricing"
              className="text-t2 hover:text-t1 transition-colors"
            >
              Pricing
            </a>
          </div>
        </div>

        {/* The cinematic — full-width 16:9 */}
        <div className="relative mt-14 sm:mt-20 mx-auto max-w-[1100px]">
          {/* Soft halo behind the frame */}
          <div
            aria-hidden
            className="pointer-events-none absolute inset-x-12 -inset-y-6 -z-10 blur-3xl opacity-50"
            style={{
              background:
                "radial-gradient(ellipse 70% 60% at 50% 50%, rgba(59,130,246,0.32) 0%, transparent 70%)",
            }}
          />
          <div className="relative aspect-video w-full overflow-hidden rounded-2xl border border-border bg-s1 shadow-[0_30px_80px_-20px_rgba(0,0,0,0.6)]">
            {hasVideo === true ? (
              <video
                ref={videoRef}
                src="/hero/loop.mp4"
                poster="/hero/poster.jpg"
                preload="auto"
                muted
                playsInline
                className="absolute inset-0 h-full w-full object-cover"
              />
            ) : (
              <div className="absolute inset-0 bg-gradient-to-br from-s1 via-s2 to-s1" />
            )}
          </div>
        </div>

        {/* Story captions — explain what just happened */}
        <div className="mt-10 grid grid-cols-1 sm:grid-cols-3 gap-px rounded-2xl border border-border bg-border overflow-hidden mx-auto max-w-[1100px]">
          <Caption
            icon={<VaultGlyph />}
            tone="amber"
            title="Real keys live in the vault"
            body="Your OS keychain. Encrypted at rest with ChaCha20-Poly1305. The amber star inside the ghost."
          />
          <Caption
            icon={<TokenGlyph />}
            tone="cyan"
            title="AI sees only the phantom"
            body="A worthless phm_ token in your .env. The card the ghost holds out. Useless if leaked."
          />
          <Caption
            icon={<WireGlyph />}
            tone="neutral"
            title="Full access, zero exposure"
            body="The local proxy swaps the token for the real key just before the TLS hop. AI delegates. Secrets stay home."
          />
        </div>
      </div>
    </header>
  );
}

function Caption({
  icon,
  title,
  body,
  tone,
}: {
  icon: React.ReactNode;
  title: string;
  body: string;
  tone: "amber" | "cyan" | "neutral";
}) {
  const ring =
    tone === "amber"
      ? "border-[#f59e0b]/25 bg-[#f59e0b]/10 text-[#fbbf24]"
      : tone === "cyan"
      ? "border-blue-d/40 bg-blue/10 text-blue-b"
      : "border-border bg-s2 text-t2";

  return (
    <article className="bg-s1 p-7 sm:p-8">
      <div
        className={
          "inline-flex h-10 w-10 items-center justify-center rounded-lg border " +
          ring
        }
      >
        {icon}
      </div>
      <h3 className="mt-4 text-[1rem] font-bold text-t1 tracking-[-0.01em]">
        {title}
      </h3>
      <p className="mt-2 text-[0.88rem] text-t2 leading-[1.6]">{body}</p>
    </article>
  );
}

/* Inline SVG glyphs — no new icon dep, monoline, sized 18px */
function VaultGlyph() {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <rect x="3" y="11" width="18" height="11" rx="2" />
      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
      <circle cx="12" cy="16.5" r="1.4" />
    </svg>
  );
}

function TokenGlyph() {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <rect x="3" y="6" width="18" height="12" rx="2" />
      <path d="M7 12h2M11 12h6" />
    </svg>
  );
}

function WireGlyph() {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <path d="M3 12h6M15 12h6" />
      <circle cx="12" cy="12" r="3" />
      <path d="M12 6v1.5M12 16.5V18" />
    </svg>
  );
}
