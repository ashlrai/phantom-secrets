import { Reveal } from "./Reveal";

const CASES = [
  {
    num: "01",
    quote: "Integrate Stripe payments",
    body: (
      <>
        Claude writes the code, tests it against your real Stripe key. The key
        flows through the proxy — Claude never sees{" "}
        <code className="text-blue-b font-mono text-[0.82rem]">sk_live_…</code>,
        but the integration works.
      </>
    ),
    tag: "Payments",
  },
  {
    num: "02",
    quote: "Build an OpenAI chatbot",
    body: (
      <>
        Cursor reads your .env, sees{" "}
        <code className="text-blue-b font-mono text-[0.82rem]">phm_d9f1…</code>.
        It writes code that calls OpenAI. The proxy injects your real key. The
        chatbot works. The key stays safe.
      </>
    ),
    tag: "LLM APIs",
  },
  {
    num: "03",
    quote: "Deploy to Vercel",
    body: (
      <>
        Run{" "}
        <code className="text-blue-b font-mono text-[0.82rem]">
          phantom sync --platform vercel
        </code>{" "}
        to push real secrets to your deployment. No more copying keys into
        dashboards. One command, all environments.
      </>
    ),
    tag: "Deployment",
  },
  {
    num: "04",
    quote: "Set up this project on a new machine",
    body: (
      <>
        Run{" "}
        <code className="text-blue-b font-mono text-[0.82rem]">
          phantom pull --from vercel
        </code>{" "}
        to import all secrets. Your vault syncs. No Slack messages asking for
        the .env file.
      </>
    ),
    tag: "Onboarding",
  },
];

function QuoteMark({ className }: { className?: string }) {
  return (
    <svg
      width="32"
      height="24"
      viewBox="0 0 32 24"
      fill="currentColor"
      aria-hidden="true"
      className={className}
    >
      <path d="M0 24V14.4C0 6.4 4.267 1.333 12.8 0l1.6 2.4C10.133 3.733 8 6.667 8 10h4.8V24H0Zm17.6 0V14.4C17.6 6.4 21.867 1.333 30.4 0L32 2.4C27.733 3.733 25.6 6.667 25.6 10h4.8V24H17.6Z" />
    </svg>
  );
}

export function UseCases() {
  return (
    <section className="py-24 sm:py-28">
      <div className="mx-auto max-w-[1080px] px-7">
        <Reveal>
          <div className="text-center mb-14">
            <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-border bg-s1 px-3.5 py-1 text-[0.72rem] font-mono font-medium tracking-[0.06em] text-t3 uppercase">
              // use cases
            </div>
            <h2 className="text-[1.7rem] sm:text-[2.2rem] font-extrabold tracking-[-0.04em] text-white mb-3">
              Ship the things you wouldn&apos;t risk before.
            </h2>
            <p className="mx-auto max-w-[560px] text-t2 text-[0.95rem] sm:text-base leading-[1.7]">
              Phantom doesn&apos;t restrict AI — it unlocks the work you used
              to keep it away from. Real APIs, real databases, real production.
            </p>
          </div>
        </Reveal>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
          {CASES.map((c, i) => (
            <Reveal key={c.quote} delay={i * 0.04}>
              <article className="group h-full rounded-2xl border border-border bg-s1 p-7 sm:p-8 transition-all duration-200 hover:border-border-l hover:-translate-y-0.5 relative overflow-hidden">
                {/* Subtle top-left accent glow */}
                <div className="pointer-events-none absolute -top-8 -left-8 h-24 w-24 rounded-full bg-blue/[0.07] blur-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-500" />

                {/* Header row */}
                <div className="flex items-start justify-between mb-5">
                  <QuoteMark className="text-blue-d/40 flex-shrink-0 mt-0.5" />
                  <div className="flex items-center gap-2.5">
                    <span className="font-mono text-[0.68rem] font-semibold text-t3 tracking-[0.04em]">
                      {c.num}
                    </span>
                    <span className="rounded-md border border-border bg-s2 px-2 py-0.5 text-[0.68rem] font-mono text-t3">
                      {c.tag}
                    </span>
                  </div>
                </div>

                {/* Quote */}
                <h3 className="text-[1.05rem] font-bold italic text-t1 mb-3 leading-snug tracking-[-0.01em]">
                  &ldquo;{c.quote}&rdquo;
                </h3>

                {/* Body */}
                <p className="text-t2 text-[0.88rem] leading-[1.65]">{c.body}</p>
              </article>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}
