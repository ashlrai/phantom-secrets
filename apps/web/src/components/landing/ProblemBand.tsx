import { Reveal } from "./Reveal";

const STATS = [
  {
    n: "39.6M",
    label: "secrets leaked on GitHub in 2025",
    sub: "GitGuardian State of Secrets Sprawl",
    trend: "+81%",
    trendLabel: "YoY",
    color: "red" as const,
  },
  {
    n: "2×",
    label: "higher leak rate with AI-assisted commits",
    sub: "Correlation with AI coding tool usage",
    trend: "↑",
    trendLabel: "accelerating",
    color: "red" as const,
  },
  {
    n: "$4.9M",
    label: "average cost of a secrets-related breach",
    sub: "IBM Cost of Data Breach 2024",
    trend: "▲",
    trendLabel: "record high",
    color: "red" as const,
  },
];

// Tiny SVG sparkline — a jagged upward trend, purely decorative
function TrendLine({ color }: { color: string }) {
  return (
    <svg
      width="64"
      height="20"
      viewBox="0 0 64 20"
      fill="none"
      aria-hidden="true"
      className={`text-${color} opacity-60`}
    >
      <polyline
        points="0,18 10,14 20,16 30,10 40,12 52,4 64,2"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export function ProblemBand() {
  return (
    <section id="why" className="border-t border-border py-24 sm:py-28 relative overflow-hidden">
      {/* Subtle red ambient wash behind the stats */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 flex items-center justify-center"
      >
        <div className="h-[400px] w-[700px] rounded-full bg-red/[0.04] blur-[120px]" />
      </div>

      <div className="relative mx-auto max-w-[1080px] px-7">
        <Reveal>
          <div className="text-center mb-14">
            {/* Eyebrow chip */}
            <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-border bg-s1 px-3.5 py-1 text-[0.72rem] font-mono font-medium tracking-[0.06em] text-t3 uppercase">
              <span className="inline-block h-1.5 w-1.5 rounded-full bg-red animate-pulse" />
              // threat landscape
            </div>
            <h2 className="text-[1.7rem] sm:text-[2.2rem] font-extrabold tracking-[-0.04em] text-white mb-3">
              The risk is the only thing holding you back.
            </h2>
            <p className="mx-auto max-w-[560px] text-t2 text-[0.95rem] sm:text-base leading-[1.7]">
              You ration what AI gets to touch because one paste is one leak
              away. The Stripe key stays in your head. The prod database URL
              lives in 1Password. Phantom ends the rationing.
            </p>
          </div>
        </Reveal>

        <Reveal delay={0.05}>
          <div className="grid grid-cols-1 sm:grid-cols-3 divide-y sm:divide-y-0 sm:divide-x divide-border border border-border rounded-2xl overflow-hidden bg-s1">
            {STATS.map((s, i) => (
              <div
                key={s.label}
                className="relative group px-8 py-10 sm:py-12 flex flex-col gap-3"
              >
                {/* Top accent line */}
                <div className="absolute top-0 left-8 right-8 h-px bg-gradient-to-r from-transparent via-red/50 to-transparent" />

                {/* Stat number */}
                <div className="font-black tracking-[-0.04em] text-white leading-none text-[clamp(2.2rem,4.5vw,3rem)]">
                  {s.n}
                </div>

                {/* Sparkline */}
                <TrendLine color={s.color} />

                {/* Label */}
                <div className="text-t2 text-[0.84rem] leading-[1.5] font-medium">
                  {s.label}
                </div>

                {/* Trend badge + source */}
                <div className="flex items-center gap-2 mt-auto">
                  <span className="inline-flex items-center gap-1 rounded-md bg-red/10 px-2 py-0.5 text-[0.7rem] font-mono font-semibold text-red">
                    {s.trend} {s.trendLabel}
                  </span>
                </div>
                <div className="text-[0.68rem] text-t3 font-mono leading-tight">
                  {s.sub}
                </div>
              </div>
            ))}
          </div>
        </Reveal>
      </div>
    </section>
  );
}
