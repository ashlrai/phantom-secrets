"use client";

import { motion } from "motion/react";
import { CopyButton } from "./CopyButton";
import { Hero3D } from "./Hero3D";
import { easeOutExpo } from "./motion";

const fadeUp = (delay = 0) => ({
  initial: { opacity: 0, y: 24 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.7, delay, ease: easeOutExpo },
});

export function Hero() {
  return (
    <header className="relative overflow-x-clip">
      <div className="hero-wash" aria-hidden />

      <div className="relative mx-auto max-w-[1240px] px-7 pt-16 sm:pt-20 pb-16 sm:pb-24">
        <div className="grid grid-cols-1 lg:grid-cols-[1.05fr_1fr] gap-10 lg:gap-14 items-center">
          {/* LEFT — text */}
          <div className="text-center lg:text-left">
            <motion.div
              {...fadeUp(0)}
              className="inline-flex items-center gap-2 rounded-full border border-border bg-s1 px-3 py-1 text-[0.72rem] font-medium text-t2 mb-6"
            >
              <span className="relative flex h-1.5 w-1.5">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-blue/60 opacity-75" />
                <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-blue" />
              </span>
              For every AI coding tool · Open source · MIT
            </motion.div>

            <motion.h1
              {...fadeUp(0.08)}
              className="font-black tracking-[-0.04em] leading-[1.02] text-white text-[clamp(2.1rem,4.6vw,3.6rem)]"
            >
              Delegate everything to AI.
              <br />
              <span className="bg-gradient-to-br from-blue-b via-blue to-blue-d bg-clip-text text-transparent">
                Without sharing a single key.
              </span>
            </motion.h1>

            <motion.p
              {...fadeUp(0.16)}
              className="mt-5 max-w-[520px] mx-auto lg:mx-0 text-[0.95rem] sm:text-base text-t2 leading-[1.7]"
            >
              AI coding tools want your API keys. Pasting them in works — until
              they leak. Phantom hands AI a worthless token and injects the real
              key at the network layer. Full access. Zero exposure.
            </motion.p>

            <motion.div
              {...fadeUp(0.24)}
              className="mt-7 max-w-[440px] mx-auto lg:mx-0"
            >
              <CopyButton text="npx phantom-secrets init" />
              <p className="mt-2.5 text-[0.76rem] text-t3 leading-relaxed">
                Protects <code className="text-blue-b">.env</code>. Sets up MCP
                for Claude Code, Cursor, Windsurf, Codex.
              </p>
            </motion.div>

            <motion.div
              {...fadeUp(0.32)}
              className="mt-6 flex flex-wrap justify-center lg:justify-start gap-2.5"
            >
              <a
                href="#why"
                className="inline-flex items-center gap-2 rounded-lg border border-blue bg-blue px-5 py-2.5 text-[0.9rem] font-semibold text-white no-underline transition-all duration-200 hover:bg-blue-d hover:-translate-y-px hover:shadow-[0_4px_24px_rgba(59,130,246,0.32)] hover-lift"
              >
                Why Phantom?
              </a>
              <a
                href="#how"
                className="inline-flex items-center gap-2 rounded-lg border border-border-l px-5 py-2.5 text-[0.9rem] font-semibold text-t1 no-underline transition-colors duration-200 hover:border-t3"
              >
                How it works
              </a>
            </motion.div>
          </div>

          {/* RIGHT — 3D scene */}
          <motion.div
            initial={{ opacity: 0, scale: 0.96 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 1.1, delay: 0.2, ease: easeOutExpo }}
            className="relative"
          >
            <Hero3D />
          </motion.div>
        </div>
      </div>
    </header>
  );
}
