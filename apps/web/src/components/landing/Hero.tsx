"use client";

import { motion, useReducedMotion } from "motion/react";
import { useEffect, useRef, useState } from "react";
import { CopyButton } from "./CopyButton";
import { easeOutExpo } from "./motion";

const fadeUp = (delay = 0) => ({
  initial: { opacity: 0, y: 18 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.7, delay, ease: easeOutExpo },
});

export function Hero() {
  const sectionRef = useRef<HTMLElement>(null);
  const videoRef = useRef<HTMLVideoElement>(null);
  const reduce = useReducedMotion();
  const [hasVideo, setHasVideo] = useState<boolean | null>(null);
  const [isMobile, setIsMobile] = useState(false);

  // Probe for the video file. If absent (assets not generated yet) we render
  // the animated CSS fallback so the page isn't broken.
  useEffect(() => {
    fetch("/hero/loop.mp4", { method: "HEAD" })
      .then((r) => setHasVideo(r.ok && r.headers.get("content-type")?.startsWith("video") !== false))
      .catch(() => setHasVideo(false));
    setIsMobile(window.matchMedia("(max-width: 768px)").matches);
  }, []);

  // Scroll-driven playback (desktop, video present, motion allowed).
  useEffect(() => {
    if (!hasVideo || reduce || isMobile) return;
    const video = videoRef.current;
    const section = sectionRef.current;
    if (!video || !section) return;

    let raf = 0;
    const apply = () => {
      const rect = section.getBoundingClientRect();
      const total = section.offsetHeight - window.innerHeight;
      if (total <= 0) return;
      const progress = Math.min(1, Math.max(0, -rect.top / total));
      if (Number.isFinite(video.duration) && video.duration > 0) {
        video.currentTime = progress * video.duration;
      }
    };
    const onScroll = () => {
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(apply);
    };
    apply();
    window.addEventListener("scroll", onScroll, { passive: true });
    video.addEventListener("loadedmetadata", apply);
    return () => {
      window.removeEventListener("scroll", onScroll);
      video.removeEventListener("loadedmetadata", apply);
      cancelAnimationFrame(raf);
    };
  }, [hasVideo, reduce, isMobile]);

  // Mobile / reduced-motion: just autoplay the loop.
  useEffect(() => {
    if (!hasVideo) return;
    const video = videoRef.current;
    if (!video) return;
    if (reduce || isMobile) {
      video.loop = true;
      video.play().catch(() => {});
    }
  }, [hasVideo, reduce, isMobile]);

  return (
    <header
      ref={sectionRef}
      className="relative h-svh lg:h-[220svh] bg-bg"
      aria-label="Phantom — delegate everything to AI without sharing a single key"
    >
      <div className="sticky top-0 h-svh w-full overflow-hidden">
        {/* Visual layer — video if assets exist, else animated fallback */}
        {hasVideo === true ? (
          <video
            ref={videoRef}
            src="/hero/loop.mp4"
            poster="/hero/poster.jpg"
            preload="auto"
            muted
            playsInline
            disablePictureInPicture
            className="absolute inset-0 h-full w-full object-cover"
          />
        ) : (
          <FallbackBackdrop />
        )}

        {/* Contrast wash so text stays legible no matter the frame */}
        <div
          aria-hidden
          className="pointer-events-none absolute inset-0 bg-gradient-to-b from-bg/55 via-bg/15 to-bg/90"
        />
        <div
          aria-hidden
          className="pointer-events-none absolute inset-0 bg-gradient-to-r from-bg/45 via-transparent to-bg/45"
        />

        {/* Foreground content */}
        <div className="relative z-10 flex h-full flex-col items-center justify-center px-7 text-center">
          <motion.div {...fadeUp(0)}>
            <span className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.04] px-3 py-1 text-[0.72rem] font-medium text-white/80 backdrop-blur-md">
              <span className="relative flex h-1.5 w-1.5">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-blue/60 opacity-75" />
                <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-blue" />
              </span>
              For every AI coding tool · Open source · MIT
            </span>
          </motion.div>

          <motion.h1
            {...fadeUp(0.08)}
            className="mt-7 max-w-[940px] font-black tracking-[-0.04em] leading-[1.02] text-white text-[clamp(2.4rem,5.6vw,4.4rem)]"
          >
            Delegate everything to AI.
            <br />
            <span className="bg-gradient-to-br from-blue-b via-blue to-blue-d bg-clip-text text-transparent">
              Without sharing a single key.
            </span>
          </motion.h1>

          <motion.p
            {...fadeUp(0.16)}
            className="mt-6 max-w-[580px] text-[0.95rem] sm:text-base leading-[1.7] text-white/75"
          >
            AI coding tools want your API keys. Pasting them in works — until
            they leak. Phantom hands AI a worthless token and injects the real
            key at the network layer. Full access. Zero exposure.
          </motion.p>

          <motion.div
            {...fadeUp(0.24)}
            className="mt-8 w-full max-w-[460px]"
          >
            <CopyButton text="npx phantom-secrets init" />
            <p className="mt-2.5 text-[0.76rem] text-white/55 leading-relaxed">
              Protects <code className="text-blue-b">.env</code>. Sets up MCP for
              Claude Code, Cursor, Windsurf, Codex.
            </p>
          </motion.div>

          <motion.div
            {...fadeUp(0.32)}
            className="mt-7 flex flex-wrap justify-center gap-2.5"
          >
            <a
              href="#why"
              className="inline-flex items-center gap-2 rounded-lg border border-blue bg-blue px-5 py-2.5 text-[0.9rem] font-semibold text-white no-underline transition-all duration-200 hover:bg-blue-d hover:-translate-y-px hover:shadow-[0_4px_24px_rgba(59,130,246,0.32)] hover-lift"
            >
              Why Phantom?
            </a>
            <a
              href="#how"
              className="inline-flex items-center gap-2 rounded-lg border border-white/15 bg-white/[0.04] px-5 py-2.5 text-[0.9rem] font-semibold text-white no-underline transition-colors duration-200 hover:border-white/30 hover:bg-white/[0.08] backdrop-blur-md"
            >
              How it works
            </a>
          </motion.div>

          {/* Scroll hint — only when scroll-driven story is live */}
          {hasVideo === true && !isMobile && !reduce && (
            <motion.div
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 1.3, duration: 0.9, ease: easeOutExpo }}
              className="absolute bottom-9 left-1/2 -translate-x-1/2 flex flex-col items-center gap-2 text-[0.7rem] tracking-[0.18em] uppercase text-white/45"
            >
              Scroll to see how
              <motion.span
                aria-hidden
                animate={{ y: [0, 6, 0] }}
                transition={{ duration: 1.6, repeat: Infinity, ease: "easeInOut" }}
                className="block h-6 w-px bg-gradient-to-b from-white/40 to-transparent"
              />
            </motion.div>
          )}
        </div>
      </div>
    </header>
  );
}

function FallbackBackdrop() {
  // Stand-in until /public/hero/loop.mp4 is generated. Animated radial fields
  // plus a slow drifting particle layer so the hero never looks static.
  return (
    <div aria-hidden className="absolute inset-0 overflow-hidden bg-bg">
      {/* Two layered radial gradients with slow CSS animation */}
      <div
        className="absolute inset-0 animate-[heroPulse_9s_ease-in-out_infinite]"
        style={{
          background:
            "radial-gradient(ellipse 70% 55% at 50% 38%, rgba(59,130,246,0.55) 0%, transparent 65%)",
        }}
      />
      <div
        className="absolute inset-0 animate-[heroDrift_14s_ease-in-out_infinite]"
        style={{
          background:
            "radial-gradient(ellipse 50% 70% at 30% 70%, rgba(96,165,250,0.32) 0%, transparent 60%)",
        }}
      />
      <div
        className="absolute inset-0 animate-[heroDrift2_18s_ease-in-out_infinite]"
        style={{
          background:
            "radial-gradient(ellipse 55% 60% at 75% 35%, rgba(29,78,216,0.32) 0%, transparent 60%)",
        }}
      />
      {/* Faint grid texture for visual interest */}
      <div
        className="absolute inset-0 opacity-[0.04]"
        style={{
          backgroundImage:
            "linear-gradient(rgba(255,255,255,0.5) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.5) 1px, transparent 1px)",
          backgroundSize: "44px 44px",
          maskImage:
            "radial-gradient(ellipse 70% 70% at 50% 50%, black 30%, transparent 75%)",
        }}
      />
      <style>{`
        @keyframes heroPulse {
          0%, 100% { transform: translate(0, 0) scale(1); opacity: 1; }
          50% { transform: translate(0, -20px) scale(1.06); opacity: 0.85; }
        }
        @keyframes heroDrift {
          0%, 100% { transform: translate(0, 0); }
          50% { transform: translate(40px, -30px); }
        }
        @keyframes heroDrift2 {
          0%, 100% { transform: translate(0, 0); }
          50% { transform: translate(-50px, 25px); }
        }
      `}</style>
    </div>
  );
}
