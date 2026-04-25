import { CopyButton } from "./CopyButton";
import { Github } from "./Icons";
import { Reveal } from "./Reveal";

export function CTA() {
  return (
    <section className="relative overflow-x-clip border-t border-border py-28 sm:py-40">
      {/* Background wash */}
      <div className="cta-wash" aria-hidden />

      {/* Deep ambient glow — two overlapping orbs */}
      <div
        aria-hidden
        className="pointer-events-none absolute left-1/2 top-0 -translate-x-1/2 h-[600px] w-[900px] rounded-full bg-blue/[0.06] blur-[160px]"
      />
      <div
        aria-hidden
        className="pointer-events-none absolute left-1/2 top-16 -translate-x-1/2 h-[300px] w-[500px] rounded-full bg-blue-b/[0.04] blur-[100px]"
      />

      <div className="relative mx-auto max-w-[1080px] px-7 text-center">
        <Reveal>
          {/* Animated gradient eyebrow bar */}
          <div className="mb-8 flex justify-center">
            <div className="relative h-px w-40 overflow-hidden rounded-full">
              <div className="absolute inset-0 bg-gradient-to-r from-transparent via-blue-b to-transparent animate-[shimmer_2.5s_ease-in-out_infinite]" />
            </div>
          </div>

          {/* Eyebrow chip */}
          <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-blue-d/40 bg-blue/10 px-4 py-1.5 text-[0.72rem] font-mono font-medium tracking-[0.08em] text-blue-b uppercase">
            <span className="inline-block h-1.5 w-1.5 rounded-full bg-blue-b" />
            ready to ship
          </div>

          <h2 className="font-black tracking-[-0.045em] leading-[0.95] text-white text-[clamp(2.4rem,6.5vw,4rem)] mb-5">
            Stop rationing.
            <br />
            <span className="text-t2">Start delegating.</span>
          </h2>
          <p className="mx-auto max-w-[480px] text-t2 text-[0.95rem] sm:text-base leading-[1.7]">
            One command. Real keys never leave your machine. AI gets to
            work on what matters.
          </p>
        </Reveal>

        <Reveal delay={0.08}>
          <div className="mx-auto mt-10 max-w-[460px]">
            <CopyButton text="npx phantom-secrets init" />
          </div>
        </Reveal>

        <Reveal delay={0.14}>
          <div className="mt-8 flex flex-wrap justify-center gap-2.5">
            <a
              href="https://github.com/ashlrai/phantom-secrets"
              className="inline-flex items-center gap-2 rounded-lg border border-border-l bg-s1/60 backdrop-blur-sm px-5 py-2.5 text-[0.88rem] font-semibold text-t2 no-underline transition-all duration-150 hover:border-t3 hover:text-t1"
            >
              <Github className="w-[15px] h-[15px]" />
              View on GitHub
            </a>
            <a
              href="/pricing"
              className="inline-flex items-center gap-2 rounded-lg border border-border-l bg-s1/60 backdrop-blur-sm px-5 py-2.5 text-[0.88rem] font-semibold text-t2 no-underline transition-all duration-150 hover:border-t3 hover:text-t1"
            >
              Pricing
            </a>
          </div>

          {/* Fine print */}
          <p className="mt-6 text-[0.75rem] font-mono text-t3">
            MIT licensed · local-first · no secrets leave your machine
          </p>
        </Reveal>
      </div>
    </section>
  );
}
