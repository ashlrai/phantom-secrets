import { Reveal } from "./Reveal";

const ITEMS = [
  {
    title: "Open source. MIT licensed.",
    body: (
      <>
        Every line of code is on GitHub. Fork it, audit it, self-host it. 56
        tests, zero clippy warnings. Written in Rust for memory safety.
      </>
    ),
  },
  {
    title: "Zero-knowledge cloud.",
    body: (
      <>
        Cloud sync encrypts with ChaCha20-Poly1305 before upload. The encryption
        key never leaves your machine. We literally cannot read your secrets.
      </>
    ),
  },
  {
    title: "Your keys never leave your machine.",
    body: (
      <>
        Real secrets live in your OS keychain (macOS Keychain, Linux Secret
        Service). The proxy runs on 127.0.0.1 only. Nothing is sent to us
        unless you opt into cloud sync.
      </>
    ),
  },
  {
    title: "No lock-in. Remove in 10 seconds.",
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
      className="border-t border-border py-24 sm:py-28"
    >
      <div className="mx-auto max-w-[1080px] px-7">
        <Reveal>
          <div className="text-center mb-14">
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
              <article className="h-full rounded-2xl border border-border bg-s1 p-7 sm:p-8 transition-colors hover:border-border-l">
                <h3 className="text-base font-bold text-t1 mb-2">
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
