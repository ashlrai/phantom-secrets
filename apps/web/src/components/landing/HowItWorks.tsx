import Image from "next/image";

const STEPS = [
  {
    n: "1",
    title: "Read your .env",
    body: (
      <>
        Phantom auto-detects 13+ services and replaces real values with{" "}
        <code className="font-mono text-blue-b">phm_</code> tokens.
      </>
    ),
  },
  {
    n: "2",
    title: "Lock in the vault",
    body: (
      <>
        Real keys move to your OS keychain. ChaCha20-Poly1305 + Argon2id.
        Encrypted-file fallback for CI and Docker.
      </>
    ),
  },
  {
    n: "3",
    title: "Authenticate exact routes",
    body: (
      <>
        Supported SDKs use the authenticated proxy on{" "}
        <code className="font-mono text-blue-b">127.0.0.1</code>. It matches an
        exact route and injects only that route&apos;s vault value into its fixed
        auth header before forwarding over TLS. Client placeholders stay inert.
      </>
    ),
  },
];

export function HowItWorks() {
  return (
    <section id="how" className="border-t border-border py-24 sm:py-32">
      <div className="mx-auto max-w-[1100px] px-7">
        <div className="max-w-[640px]">
          <h2 className="text-[1.8rem] sm:text-[2.4rem] font-extrabold tracking-[-0.035em] leading-[1.08] text-white">
            One CLI. Three layers.
          </h2>
          <p className="mt-4 text-[0.98rem] text-t2 leading-[1.65]">
            Phantom keeps real secrets out of supported, value-blind agent paths.
            Human plaintext reveal remains a separate trusted-terminal workflow.
          </p>
        </div>

        <div className="mt-12 rounded-2xl border border-border bg-s1 overflow-hidden">
          <Image
            src="/architecture-diagram.png"
            alt="Architecture diagram: .env file with phm_ tokens flows through local proxy and vault to AI tools"
            width={1920}
            height={1080}
            sizes="(max-width: 768px) 100vw, 1100px"
            className="w-full h-auto"
          />
        </div>

        <div className="mt-12 grid grid-cols-1 lg:grid-cols-3 gap-px bg-border border border-border rounded-2xl overflow-hidden">
          {STEPS.map((s) => (
            <article key={s.n} className="bg-s1 p-7 sm:p-8">
              <div className="font-mono text-[0.78rem] text-blue-b mb-3">
                Step {s.n}
              </div>
              <h3 className="text-[1.05rem] font-bold text-t1 mb-2">
                {s.title}
              </h3>
              <p className="text-[0.9rem] text-t2 leading-[1.65]">{s.body}</p>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
