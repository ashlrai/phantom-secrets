import { Check } from "./Icons";
import { Reveal } from "./Reveal";

const CASES = [
  {
    quote: "Integrate Stripe payments",
    body: (
      <>
        Claude writes the code, tests it against your real Stripe key. The key
        flows through the proxy — Claude never sees{" "}
        <code className="text-blue-b font-mono text-[0.82rem]">sk_live_…</code>,
        but the integration works.
      </>
    ),
  },
  {
    quote: "Build an OpenAI chatbot",
    body: (
      <>
        Cursor reads your .env, sees{" "}
        <code className="text-blue-b font-mono text-[0.82rem]">phm_d9f1…</code>.
        It writes code that calls OpenAI. The proxy injects your real key. The
        chatbot works. The key stays safe.
      </>
    ),
  },
  {
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
  },
  {
    quote: "Set up this project on my new laptop",
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
  },
];

export function UseCases() {
  return (
    <section className="py-24 sm:py-28">
      <div className="mx-auto max-w-[1080px] px-7">
        <Reveal>
          <div className="text-center mb-14">
            <h2 className="text-[1.7rem] sm:text-[2.2rem] font-extrabold tracking-[-0.04em] text-white mb-3">
              Now you can ship the things you wouldn&apos;t risk before.
            </h2>
            <p className="mx-auto max-w-[560px] text-t2 text-[0.95rem] sm:text-base leading-[1.7]">
              Phantom doesn&apos;t restrict AI — it unlocks the work you used
              to keep it away from. Real APIs, real databases, real production.
              Everything just works.
            </p>
          </div>
        </Reveal>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
          {CASES.map((c, i) => (
            <Reveal key={c.quote} delay={i * 0.04}>
              <article className="group h-full rounded-2xl border border-border bg-s1 p-7 sm:p-8 transition-all duration-200 hover:border-border-l hover:-translate-y-px hover-lift">
                <div className="mb-4 inline-flex items-center justify-center w-7 h-7 rounded-lg bg-green/15 text-green">
                  <Check className="w-4 h-4" strokeWidth={2.4} />
                </div>
                <h3 className="text-base font-bold text-t1 mb-2">
                  &ldquo;{c.quote}&rdquo;
                </h3>
                <p className="text-t2 text-[0.88rem] leading-[1.65]">{c.body}</p>
              </article>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}
