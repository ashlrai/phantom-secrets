import { CopyButton } from "./CopyButton";
import { Github } from "./Icons";
import { Reveal } from "./Reveal";

export function CTA() {
  return (
    <section className="relative overflow-x-clip border-t border-border py-28 sm:py-32">
      <div className="cta-wash" aria-hidden />
      <div className="relative mx-auto max-w-[1080px] px-7 text-center">
        <Reveal>
          <h2 className="font-black tracking-[-0.04em] leading-[0.98] text-white text-[clamp(2rem,5.5vw,3rem)]">
            Stop rationing.
            <br />
            Start delegating.
          </h2>
          <p className="mt-4 text-t2 text-[0.95rem] sm:text-base leading-[1.7]">
            One command. Real keys never leave your machine. AI gets to work.
          </p>
        </Reveal>

        <Reveal delay={0.1}>
          <div className="mx-auto mt-8 max-w-[420px]">
            <CopyButton text="npx phantom-secrets init" />
          </div>
        </Reveal>

        <Reveal delay={0.15}>
          <div className="mt-7 flex flex-wrap justify-center gap-2.5">
            <a
              href="https://github.com/ashlrai/phantom-secrets"
              className="inline-flex items-center gap-2 rounded-lg border border-border-l px-5 py-2.5 text-[0.9rem] font-semibold text-t1 no-underline transition-colors hover:border-t3"
            >
              <Github className="w-[15px] h-[15px]" />
              View on GitHub
            </a>
            <a
              href="/pricing"
              className="inline-flex items-center gap-2 rounded-lg border border-border-l px-5 py-2.5 text-[0.9rem] font-semibold text-t1 no-underline transition-colors hover:border-t3"
            >
              Pricing
            </a>
          </div>
        </Reveal>
      </div>
    </section>
  );
}
