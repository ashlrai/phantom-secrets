"use client";

import Image from "next/image";
import { motion } from "motion/react";
import { Reveal } from "./Reveal";
import { easeOutExpo } from "./motion";

const STEPS = [
  {
    n: "01",
    title: "Phantom reads your .env",
    body: (
      <>
        Auto-detects 13+ services. Replaces real values with worthless{" "}
        <code className="font-mono text-blue-b">phm_</code> tokens. Backs up
        the original.
      </>
    ),
  },
  {
    n: "02",
    title: "Real keys move to your vault",
    body: (
      <>
        OS keychain on macOS / Linux, encrypted file fallback elsewhere.
        ChaCha20-Poly1305 + Argon2id. Never touches our servers unless you
        opt into cloud sync.
      </>
    ),
  },
  {
    n: "03",
    title: "Local proxy injects on the wire",
    body: (
      <>
        AI calls your API with{" "}
        <code className="font-mono text-blue-b">phm_</code> token. The proxy
        on <code className="font-mono text-blue-b">127.0.0.1</code> swaps it
        for the real key and forwards over TLS. AI never sees a real
        secret.
      </>
    ),
  },
];

export function HowItWorks() {
  return (
    <section id="how" className="relative border-t border-border py-24 sm:py-32">
      {/* Soft accent glow */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-x-0 top-0 h-[60%] opacity-50"
        style={{
          background:
            "radial-gradient(ellipse 60% 80% at 50% 0%, rgba(59,130,246,0.18) 0%, transparent 70%)",
        }}
      />

      <div className="relative mx-auto max-w-[1200px] px-7">
        <Reveal>
          <div className="text-center mb-12 sm:mb-16">
            <span className="inline-flex items-center gap-2 rounded-full border border-border bg-s1 px-3 py-1 text-[0.7rem] font-semibold uppercase tracking-[0.12em] text-blue-b">
              How it works
            </span>
            <h2 className="mt-4 text-[1.9rem] sm:text-[2.6rem] font-extrabold tracking-[-0.04em] text-white leading-[1.05]">
              One CLI. Three layers.
              <br />
              <span className="text-t2">Real secrets never leave your machine.</span>
            </h2>
          </div>
        </Reveal>

        {/* Architecture diagram — the visual centerpiece */}
        <Reveal delay={0.06}>
          <div className="relative mx-auto max-w-[1100px]">
            {/* Halo behind the diagram */}
            <div
              aria-hidden
              className="pointer-events-none absolute inset-0 -z-10 blur-3xl opacity-60 scale-90"
              style={{
                background:
                  "radial-gradient(ellipse 70% 60% at 50% 50%, rgba(59,130,246,0.35) 0%, transparent 65%)",
              }}
            />
            <motion.div
              initial={{ opacity: 0, scale: 0.96 }}
              whileInView={{ opacity: 1, scale: 1 }}
              viewport={{ once: true, margin: "0px 0px -10% 0px" }}
              transition={{ duration: 0.9, ease: easeOutExpo }}
              className="relative rounded-2xl overflow-hidden border border-border bg-s1/60 backdrop-blur-sm shadow-[0_30px_80px_-20px_rgba(0,0,0,0.6)]"
            >
              <Image
                src="/architecture-diagram.png"
                alt="Architecture diagram: .env file with phm_ tokens flows through local proxy and vault to AI tools (OpenAI, Anthropic, Stripe, etc.)"
                width={1920}
                height={1080}
                priority
                className="w-full h-auto"
              />
            </motion.div>
          </div>
        </Reveal>

        {/* Three steps */}
        <div className="mt-16 sm:mt-24 grid grid-cols-1 md:grid-cols-3 gap-4 sm:gap-5">
          {STEPS.map((s, i) => (
            <Reveal key={s.n} delay={i * 0.08}>
              <article className="group relative h-full rounded-2xl border border-border bg-s1 p-7 sm:p-8 transition-colors hover:border-blue-d/60">
                <div className="font-mono text-[0.75rem] font-bold tracking-[0.2em] text-blue-b/80 mb-5">
                  {s.n}
                </div>
                <h3 className="text-[1.1rem] sm:text-[1.2rem] font-bold text-white mb-3 leading-tight tracking-[-0.01em]">
                  {s.title}
                </h3>
                <p className="text-[0.9rem] sm:text-[0.95rem] text-t2 leading-[1.65]">
                  {s.body}
                </p>
              </article>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}
