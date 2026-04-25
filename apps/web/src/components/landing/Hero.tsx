"use client";

import { useEffect, useRef, useState } from "react";
import { posthog } from "@/lib/posthog";
import { CopyButton } from "./CopyButton";
import { Github } from "./Icons";

/**
 * Story-driven hero. The video sits behind everything as a full-bleed
 * background. As the user scrolls through the 1.5-viewport hero region,
 * five text beats cross-fade in and out. On desktop, scroll progress
 * also scrubs `video.currentTime` so the cinematic moves with the user.
 * On mobile / reduced-motion, the video just autoplays its loop.
 */
export function Hero() {
  const sectionRef = useRef<HTMLElement>(null);
  const videoRef = useRef<HTMLVideoElement>(null);
  const [progress, setProgress] = useState(0);
  const [hasVideo, setHasVideo] = useState<boolean | null>(null);
  const [scrubbable, setScrubbable] = useState(false);

  // Probe for the video file
  useEffect(() => {
    fetch("/hero/loop.mp4", { method: "HEAD" })
      .then((r) => setHasVideo(r.ok))
      .catch(() => setHasVideo(false));
  }, []);

  // Decide whether to scroll-scrub (desktop) or autoplay-loop (mobile / RM)
  useEffect(() => {
    if (typeof window === "undefined") return;
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const small = window.matchMedia("(max-width: 768px)").matches;
    setScrubbable(!reduce && !small);
  }, []);

  // Track scroll progress through the hero region (0..1)
  useEffect(() => {
    const section = sectionRef.current;
    if (!section) return;

    let raf = 0;
    const apply = () => {
      const rect = section.getBoundingClientRect();
      const total = section.offsetHeight - window.innerHeight;
      if (total <= 0) {
        setProgress(0);
        return;
      }
      const p = Math.min(1, Math.max(0, -rect.top / total));
      setProgress(p);

      const video = videoRef.current;
      if (scrubbable && video && Number.isFinite(video.duration) && video.duration > 0) {
        video.currentTime = p * video.duration;
      }
    };
    const onScroll = () => {
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(apply);
    };
    apply();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => {
      window.removeEventListener("scroll", onScroll);
      cancelAnimationFrame(raf);
    };
  }, [scrubbable]);

  // On mobile / RM, just play the loop
  useEffect(() => {
    if (!hasVideo || scrubbable) return;
    const video = videoRef.current;
    if (!video) return;
    video.loop = true;
    video.play().catch(() => {});
  }, [hasVideo, scrubbable]);

  return (
    <header
      ref={sectionRef}
      className="relative h-[150svh] bg-bg"
      aria-label="Phantom — delegate everything to AI without sharing a single key"
    >
      <div className="sticky top-0 h-svh w-full overflow-hidden">
        {/* Background video */}
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
          <FallbackBackdrop />
        )}

        {/* Contrast washes — strong, so text always reads */}
        <div
          aria-hidden
          className="pointer-events-none absolute inset-0 bg-gradient-to-b from-bg/55 via-bg/40 to-bg/85"
        />
        <div
          aria-hidden
          className="pointer-events-none absolute inset-0 bg-gradient-to-r from-bg/35 via-transparent to-bg/35"
        />

        {/* Eyebrow chip — pinned top center, visible the entire scroll */}
        <div className="absolute inset-x-0 top-20 sm:top-24 flex justify-center pointer-events-none">
          <span
            className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.04] px-3 py-1 text-[0.72rem] font-medium text-white/85 backdrop-blur-md transition-opacity duration-500"
            style={{ opacity: progress < 0.85 ? 1 : 0 }}
          >
            <span className="relative flex h-1.5 w-1.5">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-blue/60 opacity-75" />
              <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-blue" />
            </span>
            For Claude Code · Cursor · Windsurf · Codex
          </span>
        </div>

        {/* Beat stack — all centered, cross-fade */}
        <div className="absolute inset-0 flex items-center justify-center px-7">
          <div className="relative w-full max-w-[940px]">
            {BEATS.map((beat, i) => {
              const o = beatOpacity(progress, beat.center, i === BEATS.length - 1);
              const y = (1 - o) * 16;
              return (
                <div
                  key={i}
                  aria-hidden={o < 0.05}
                  className="absolute inset-0 flex flex-col items-center justify-center text-center"
                  style={{
                    opacity: o,
                    transform: `translateY(${y}px)`,
                    pointerEvents: o > 0.6 ? "auto" : "none",
                    transition: "opacity 80ms linear, transform 80ms linear",
                  }}
                >
                  {beat.render()}
                </div>
              );
            })}
          </div>
        </div>

        {/* Scroll progress rail — bottom, only while pinned */}
        <div
          aria-hidden
          className="absolute bottom-0 left-0 right-0 h-px bg-white/5"
        >
          <div
            className="h-full bg-gradient-to-r from-blue-b via-blue to-blue-d"
            style={{ width: `${progress * 100}%` }}
          />
        </div>

        {/* Scroll hint — only at the very start */}
        <div
          aria-hidden
          className="absolute bottom-7 left-1/2 -translate-x-1/2 flex flex-col items-center gap-1.5 text-[0.65rem] tracking-[0.2em] uppercase text-white/40 transition-opacity duration-500"
          style={{ opacity: progress < 0.05 ? 1 : 0 }}
        >
          <span>Scroll</span>
          <span className="block h-5 w-px bg-gradient-to-b from-white/40 to-transparent animate-[scrollHint_1.6s_ease-in-out_infinite]" />
        </div>
      </div>

      <style>{`
        @keyframes scrollHint {
          0%, 100% { transform: translateY(0); opacity: 0.4; }
          50% { transform: translateY(5px); opacity: 1; }
        }
      `}</style>
    </header>
  );
}

/* ── Story beats ──────────────────────────────────────────────── */

const BEATS: Array<{ center: number; render: () => React.ReactNode }> = [
  // 0: Promise
  {
    center: 0.08,
    render: () => (
      <h1 className="font-extrabold tracking-[-0.045em] leading-[1.0] text-white text-[clamp(2.6rem,6.8vw,5.2rem)]">
        Delegate everything to AI.
      </h1>
    ),
  },
  // 1: Catch
  {
    center: 0.30,
    render: () => (
      <h1 className="font-extrabold tracking-[-0.045em] leading-[1.0] text-white text-[clamp(2.6rem,6.8vw,5.2rem)]">
        Without sharing
        <br />
        <span className="bg-gradient-to-br from-blue-b via-blue to-blue-d bg-clip-text text-transparent">
          a single key.
        </span>
      </h1>
    ),
  },
  // 2: Mechanism
  {
    center: 0.52,
    render: () => (
      <div>
        <h2 className="font-extrabold tracking-[-0.04em] leading-[1.05] text-white text-[clamp(2rem,4.8vw,3.4rem)]">
          AI gets a worthless{" "}
          <code className="font-mono text-blue-b text-[0.92em]">phm_</code> token.
        </h2>
        <p className="mt-5 mx-auto max-w-[600px] text-[0.98rem] sm:text-[1.04rem] text-white/75 leading-[1.65]">
          Phantom rewrites your <code className="font-mono text-blue-b">.env</code>{" "}
          and hands the decoy to every AI tool you use.
        </p>
      </div>
    ),
  },
  // 3: Outcome
  {
    center: 0.74,
    render: () => (
      <div>
        <h2 className="font-extrabold tracking-[-0.04em] leading-[1.05] text-white text-[clamp(2rem,4.8vw,3.4rem)]">
          Real secrets never leave
          <br />
          your machine.
        </h2>
        <p className="mt-5 mx-auto max-w-[600px] text-[0.98rem] sm:text-[1.04rem] text-white/75 leading-[1.65]">
          A local proxy on{" "}
          <code className="font-mono text-blue-b">127.0.0.1</code> swaps the
          token for the real key just before TLS. Nothing else changes.
        </p>
      </div>
    ),
  },
  // 4: CTA — payoff
  {
    center: 0.92,
    render: () => <CTABeat />,
  },
];

function CTABeat() {
  return (
    <div className="w-full">
      <h2 className="font-extrabold tracking-[-0.045em] leading-[1.0] text-white text-[clamp(2.2rem,5vw,3.6rem)]">
        Sixty seconds to a safe{" "}
        <code className="font-mono text-blue-b text-[0.92em]">.env</code>.
      </h2>

      <div className="mt-7 mx-auto w-full max-w-[480px]">
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
          className="inline-flex items-center gap-2 rounded-lg border border-white/15 bg-white/[0.04] px-5 py-2.5 text-[0.9rem] font-semibold text-white no-underline transition-colors duration-200 hover:border-white/30 hover:bg-white/[0.08] backdrop-blur-md"
        >
          <Github className="h-3.5 w-3.5" />
          View on GitHub
        </a>
      </div>
    </div>
  );
}

/* ── Helpers ──────────────────────────────────────────────────── */

/**
 * Bell-curve fade. Beat is fully visible at `center` and fades out
 * symmetrically on either side over `range`. The final beat (CTA)
 * stays visible after its center so the user can interact with it.
 */
function beatOpacity(progress: number, center: number, isLast: boolean) {
  const range = 0.13;
  if (isLast && progress >= center) return 1;
  const distance = Math.abs(progress - center);
  if (distance >= range) return 0;
  // Smooth-step (cubic) for a nicer fade
  const t = 1 - distance / range;
  return t * t * (3 - 2 * t);
}

function FallbackBackdrop() {
  return (
    <div aria-hidden className="absolute inset-0 overflow-hidden bg-bg">
      <div
        className="absolute inset-0"
        style={{
          background:
            "radial-gradient(ellipse 70% 55% at 50% 38%, rgba(59,130,246,0.45) 0%, transparent 65%)",
        }}
      />
      <div
        className="absolute inset-0"
        style={{
          background:
            "radial-gradient(ellipse 50% 70% at 30% 70%, rgba(96,165,250,0.28) 0%, transparent 60%)",
        }}
      />
    </div>
  );
}
