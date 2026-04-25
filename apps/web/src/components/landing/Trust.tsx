import { Reveal } from "./Reveal";

const ITEMS = [
  {
    num: "01",
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <path d="M9 12h6M12 9v6" />
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z" />
      </svg>
    ),
    badge: "MIT Licensed",
    title: "Open source. Fully auditable.",
    body: (
      <>
        Every line is on GitHub. Fork it, audit it, self-host it. 56 tests,
        zero clippy warnings. Written in Rust for memory safety. The source
        is the security model.
      </>
    ),
  },
  {
    num: "02",
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <path d="M12 22C6 22 2 17 2 12V7l10-4 10 4v5c0 5-4 10-10 10Z" />
        <path d="m9 12 2 2 4-4" />
      </svg>
    ),
    badge: "Zero-knowledge",
    title: "We cannot read your secrets.",
    body: (
      <>
        Cloud sync encrypts with ChaCha20-Poly1305 before upload. The
        encryption key never leaves your machine. Even if our servers were
        compromised, your secrets are ciphertext.
      </>
    ),
  },
  {
    num: "03",
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <rect x="3" y="11" width="18" height="11" rx="2" />
        <path d="M7 11V7a5 5 0 0 1 10 0v4" />
      </svg>
    ),
    badge: "Local-first",
    title: "Your keys never leave your machine.",
    body: (
      <>
        Real secrets live in your OS keychain — macOS Keychain, Linux Secret
        Service. The proxy binds to 127.0.0.1 only. Nothing is sent to us
        unless you opt into cloud sync.
      </>
    ),
  },
  {
    num: "04",
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <path d="M18 6 6 18M6 6l12 12" />
      </svg>
    ),
    badge: "No lock-in",
    title: "Remove in 10 seconds.",
    body: (
      <>
        Your original .env is backed up automatically. Run{" "}
        <code className="text-blue-b font-mono text-[0.82rem]">
          phantom reveal
        </code>{" "}
        to see any secret. Delete{" "}
        <code className="text-blue-b font-mono text-[0.82rem]">
          .phantom.toml
        </code>{" "}
        and restore your backup to fully remove Phantom.
      </>
    ),
  },
];

export function Trust() {
  return (
    <section
      id="trust"
      className="border-t border-border py-24 sm:py-28 relative overflow-hidden"
    >
      {/* Subtle green ambient wash */}
      <div
        aria-hidden
        className="pointer-events-none absolute right-0 top-1/2 -translate-y-1/2 h-[400px] w-[400px] rounded-full bg-green/[0.04] blur-[100px]"
      />

      <div className="relative mx-auto max-w-[1080px] px-7">
        <Reveal>
          <div className="text-center mb-14">
            <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-border bg-s1 px-3.5 py-1 text-[0.72rem] font-mono font-medium tracking-[0.06em] text-t3 uppercase">
              // security model
            </div>
            <h2 className="text-[1.7rem] sm:text-[2.2rem] font-extrabold tracking-[-0.04em] text-white mb-3">
              Why trust Phantom?
            </h2>
            <p className="mx-auto max-w-[520px] text-t2 text-[0.95rem] sm:text-base leading-[1.7]">
              Security tools earn trust through transparency, not promises.
            </p>
          </div>
        </Reveal>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
          {ITEMS.map((item, i) => (
            <Reveal key={item.title} delay={(i % 2) * 0.05}>
              <article className="group h-full rounded-2xl border border-border bg-s1 p-7 sm:p-8 transition-all duration-200 hover:border-green/30 hover:-translate-y-0.5 relative overflow-hidden">
                {/* Top accent line */}
                <div className="absolute top-0 left-7 right-7 h-px bg-gradient-to-r from-transparent via-green/30 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />

                {/* Header */}
                <div className="flex items-start justify-between mb-5">
                  <div className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-border bg-s2 text-t2">
                    {item.icon}
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[0.68rem] text-t3">{item.num}</span>
                    <span className="rounded-md border border-green/20 bg-green/10 px-2 py-0.5 text-[0.68rem] font-mono text-green">
                      {item.badge}
                    </span>
                  </div>
                </div>

                <h3 className="text-[1rem] font-bold text-t1 mb-2 tracking-[-0.01em]">
                  {item.title}
                </h3>
                <p className="text-t2 text-[0.88rem] leading-[1.65]">
                  {item.body}
                </p>
              </article>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}
