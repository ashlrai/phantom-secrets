"use client";

import { Reveal } from "./Reveal";

const ROWS = [
  {
    dimension: "What AI sees",
    without: "sk-proj-aB3xK9LmN2pQrT…",
    with: "phm_a8f2c4d9",
    withMono: true,
    withoutMono: true,
  },
  {
    dimension: "Risk if AI logs leak",
    without: "Real key compromised",
    with: "Worthless decoy",
    withMono: false,
    withoutMono: false,
  },
  {
    dimension: "Setup time",
    without: "Paste keys into every AI tool",
    with: "npx phantom-secrets init",
    withMono: true,
    withoutMono: false,
  },
  {
    dimension: "Key rotation",
    without: "Update everywhere manually",
    with: "phantom rotate",
    withMono: true,
    withoutMono: false,
  },
  {
    dimension: "Pre-commit safety",
    without: "Hope the .env isn't committed",
    with: "phantom check blocks on detection",
    withMono: false,
    withoutMono: false,
  },
  {
    dimension: "New machine onboarding",
    without: "Slack the .env file around",
    with: "phantom pull",
    withMono: true,
    withoutMono: false,
  },
];

export function Comparison() {
  return (
    <section id="comparison" className="border-t border-border py-24 sm:py-28">
      <div className="mx-auto max-w-[1080px] px-7">
        <Reveal>
          <div className="text-center mb-14">
            <p className="text-[0.75rem] font-semibold tracking-[0.12em] uppercase text-blue mb-3">
              Before vs. After
            </p>
            <h2 className="text-[1.7rem] sm:text-[2.2rem] font-extrabold tracking-[-0.04em] text-white mb-3">
              The before-and-after.
            </h2>
            <p className="mx-auto max-w-[480px] text-t2 text-[0.95rem] sm:text-base leading-[1.7]">
              Same workflow. Different security posture.
            </p>
          </div>
        </Reveal>

        <Reveal delay={0.05}>
          <div className="rounded-2xl border border-border overflow-hidden">
            {/* Column headers */}
            <div className="grid grid-cols-[1fr_1fr_1fr] border-b border-border">
              <div className="px-6 py-4 border-r border-border">
                <span className="text-[0.72rem] font-mono tracking-[0.08em] text-t3 uppercase">
                  // dimension
                </span>
              </div>
              <div className="px-6 py-4 border-r border-border bg-red/[0.04]">
                <div className="flex items-center gap-2">
                  <span className="inline-block w-2 h-2 rounded-full bg-red/70" />
                  <span className="text-[0.82rem] font-semibold text-red/80">
                    Without Phantom
                  </span>
                </div>
              </div>
              <div className="px-6 py-4 bg-blue/[0.04]">
                <div className="flex items-center gap-2">
                  <span className="inline-block w-2 h-2 rounded-full bg-blue" />
                  <span className="text-[0.82rem] font-semibold text-blue-b">
                    With Phantom
                  </span>
                </div>
              </div>
            </div>

            {/* Rows */}
            {ROWS.map((row, i) => (
              <div
                key={row.dimension}
                className={`grid grid-cols-[1fr_1fr_1fr] ${
                  i < ROWS.length - 1 ? "border-b border-border" : ""
                } group`}
              >
                {/* Dimension */}
                <div className="px-6 py-5 border-r border-border flex items-center">
                  <span className="text-[0.84rem] font-medium text-t2">
                    {row.dimension}
                  </span>
                </div>

                {/* Without */}
                <div className="px-6 py-5 border-r border-border bg-red/[0.03] group-hover:bg-red/[0.05] transition-colors flex items-center">
                  <div className="flex items-start gap-2.5">
                    <svg
                      className="w-3.5 h-3.5 text-red/60 shrink-0 mt-0.5"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth={2}
                      strokeLinecap="round"
                      viewBox="0 0 24 24"
                    >
                      <path d="M18 6 6 18M6 6l12 12" />
                    </svg>
                    <span
                      className={`text-[0.84rem] leading-[1.5] ${
                        row.withoutMono
                          ? "font-mono text-red/70"
                          : "text-red/70"
                      }`}
                    >
                      {row.without}
                    </span>
                  </div>
                </div>

                {/* With */}
                <div className="px-6 py-5 bg-blue/[0.03] group-hover:bg-blue/[0.06] transition-colors flex items-center">
                  <div className="flex items-start gap-2.5">
                    <svg
                      className="w-3.5 h-3.5 text-green shrink-0 mt-0.5"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth={2.2}
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      viewBox="0 0 24 24"
                    >
                      <path d="M20 6 9 17l-5-5" />
                    </svg>
                    <span
                      className={`text-[0.84rem] leading-[1.5] ${
                        row.withMono
                          ? "font-mono text-blue-b"
                          : "text-t1"
                      }`}
                    >
                      {row.with}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </Reveal>
      </div>
    </section>
  );
}
