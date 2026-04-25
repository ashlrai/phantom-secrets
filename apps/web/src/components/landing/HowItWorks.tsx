import { Reveal } from "./Reveal";

const STEPS = [
  {
    n: "1",
    title: "Reads your .env",
    body: (
      <>
        Scans for real secrets (API keys, tokens, connection strings). Ignores
        config values like <code className="text-blue-b font-mono text-[0.82rem]">NODE_ENV</code>.
        Auto-detects 13+ services.
      </>
    ),
  },
  {
    n: "2",
    title: "Locks them in a vault",
    body: (
      <>
        Real secrets move to your OS keychain (macOS Keychain, Linux Secret
        Service) or an encrypted file vault. ChaCha20-Poly1305 encryption.
      </>
    ),
  },
  {
    n: "3",
    title: "Rewrites .env with decoys",
    body: (
      <>
        Your .env now contains worthless{" "}
        <code className="text-blue-b font-mono text-[0.82rem]">phm_</code>{" "}
        tokens. AI reads these instead. A backup of your original .env is saved
        automatically.
      </>
    ),
  },
];

const PLUS_STEPS = [
  {
    title: "Auto-configures Claude Code",
    body: (
      <>
        Sets up the MCP server so Claude can manage your secrets directly. Adds
        .env read permission. Adds CLAUDE.md instructions. Zero manual config.
      </>
    ),
  },
  {
    title: "Everything just works",
    body: (
      <>
        Run{" "}
        <code className="text-blue-b font-mono text-[0.82rem]">phantom exec -- claude</code>{" "}
        and a local proxy injects real keys at the network layer. Your code
        works. AI never knew.
      </>
    ),
  },
];

export function HowItWorks() {
  return (
    <section id="how" className="border-t border-border py-24 sm:py-28">
      <div className="mx-auto max-w-[1080px] px-7">
        <Reveal>
          <div className="text-center mb-14">
            <h2 className="text-[1.7rem] sm:text-[2.2rem] font-extrabold tracking-[-0.04em] text-white mb-3">
              What happens when you run it
            </h2>
            <p className="mx-auto max-w-[520px] text-t2 text-[0.95rem] sm:text-base leading-[1.7]">
              One command. No config files. No accounts. Here&apos;s exactly
              what{" "}
              <code className="text-blue-b font-mono text-[0.85rem]">
                phantom init
              </code>{" "}
              does.
            </p>
          </div>
        </Reveal>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5 mb-3.5">
          {STEPS.map((s, i) => (
            <Reveal key={s.n} delay={i * 0.05}>
              <article className="group h-full rounded-2xl border border-border bg-s1 p-7 sm:p-8 text-center transition-colors hover:border-border-l">
                <div className="mx-auto inline-flex items-center justify-center w-7 h-7 rounded-lg bg-blue-d text-white font-bold text-[0.8rem] mb-4">
                  {s.n}
                </div>
                <h3 className="text-base font-bold text-t1 mb-2">{s.title}</h3>
                <p className="text-t2 text-[0.88rem] leading-[1.65]">
                  {s.body}
                </p>
              </article>
            </Reveal>
          ))}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
          {PLUS_STEPS.map((s, i) => (
            <Reveal key={s.title} delay={0.1 + i * 0.05}>
              <article className="h-full rounded-2xl border border-border bg-s1 p-7 sm:p-8 text-center transition-colors hover:border-border-l">
                <div className="mx-auto inline-flex items-center justify-center w-7 h-7 rounded-lg bg-green text-bg font-bold text-base mb-4">
                  +
                </div>
                <h3 className="text-base font-bold text-t1 mb-2">{s.title}</h3>
                <p className="text-t2 text-[0.88rem] leading-[1.65]">{s.body}</p>
              </article>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}
