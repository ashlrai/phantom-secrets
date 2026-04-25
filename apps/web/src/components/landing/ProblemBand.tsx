import { Reveal } from "./Reveal";

const STATS = [
  {
    n: "39.6M",
    label: "secrets leaked on GitHub in 2025",
  },
  {
    n: "2×",
    label: "higher leak rate with AI-assisted commits",
  },
  {
    n: "+81%",
    label: "YoY increase in AI service key leaks",
  },
];

export function ProblemBand() {
  return (
    <section id="why" className="border-t border-border py-24 sm:py-28">
      <div className="mx-auto max-w-[1080px] px-7">
        <Reveal>
          <div className="text-center mb-14">
            <h2 className="text-[1.7rem] sm:text-[2.2rem] font-extrabold tracking-[-0.04em] text-white mb-3">
              The risk is the only thing holding you back.
            </h2>
            <p className="mx-auto max-w-[560px] text-t2 text-[0.95rem] sm:text-base leading-[1.7]">
              Today you ration what AI gets to touch. The Stripe key stays in
              your head. The prod database URL lives in 1Password. AI watches
              from the sidelines — because one paste is one leak away. Phantom
              ends the rationing.
            </p>
          </div>
        </Reveal>

        <Reveal delay={0.05}>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-px bg-border border border-border rounded-2xl overflow-hidden">
            {STATS.map((s) => (
              <div
                key={s.label}
                className="bg-s1 px-6 py-10 sm:py-12 text-center"
              >
                <div className="font-black tracking-[-0.04em] text-white leading-none text-[clamp(2.4rem,5vw,3.4rem)]">
                  {s.n}
                </div>
                <div className="mt-2 text-t2 text-[0.85rem]">{s.label}</div>
              </div>
            ))}
          </div>
        </Reveal>
      </div>
    </section>
  );
}
