"use client";

import { useEffect, useRef, useState } from "react";
import { CopyButton } from "./CopyButton";

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
      <div className="mx-auto max-w-[1200px] px-7 pt-16 pb-20 sm:pt-24 sm:pb-28">
        <div className="grid grid-cols-1 gap-12 lg:grid-cols-[1.1fr_1fr] lg:gap-14 items-center">
          {/* Text */}
          <div>
            <h1 className="font-extrabold tracking-[-0.04em] leading-[1.04] text-white text-[clamp(2.4rem,5.6vw,4rem)]">
              Delegate everything to AI.
              <br />
              <span className="text-t3">Without sharing a single key.</span>
            </h1>

            <p className="mt-6 max-w-[520px] text-[0.98rem] sm:text-[1.02rem] leading-[1.65] text-t2">
              Phantom replaces your real API keys with worthless{" "}
              <code className="font-mono text-blue-b text-[0.92em]">phm_</code>{" "}
              tokens and injects the real keys at the network layer. AI gets full
              access. Your secrets never leave your machine.
            </p>

            <div className="mt-8 max-w-[440px]">
              <CopyButton text="npx phantom-secrets init" />
            </div>

            <div className="mt-5 flex flex-wrap items-center gap-x-5 gap-y-2 text-[0.84rem]">
              <a
                href="https://github.com/ashlrai/phantom-secrets"
                className="inline-flex items-center gap-1.5 text-t2 hover:text-t1 transition-colors"
              >
                <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
                  <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z" />
                </svg>
                View on GitHub
              </a>
              <span className="text-t3">·</span>
              <a href="#how" className="text-t2 hover:text-t1 transition-colors">
                How it works
              </a>
              <span className="text-t3">·</span>
              <a href="/pricing" className="text-t2 hover:text-t1 transition-colors">
                Pricing
              </a>
            </div>
          </div>

          {/* Visual */}
          <div className="relative">
            <div className="relative aspect-square w-full max-w-[520px] mx-auto rounded-2xl border border-border overflow-hidden bg-s1">
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
                <div className="absolute inset-0 bg-gradient-to-br from-s1 to-s2" />
              )}
            </div>
          </div>
        </div>
      </div>
    </header>
  );
}
