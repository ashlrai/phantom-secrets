// FAQ section — visible counterpart to the FAQPage JSON-LD in layout.tsx.
// Uses native <details>/<summary> so it works without JS, with a small
// CSS rotation on the chevron when open.

function Tok({ children }: { children: React.ReactNode }) {
  return (
    <code className="font-mono text-blue-b text-[0.92em]">{children}</code>
  );
}

const QUESTIONS: { q: string; a: React.ReactNode }[] = [
  {
    q: "Does Phantom slow down my AI requests?",
    a: (
      <>
        About 0.5 ms of proxy overhead per request — not measurable in
        practice. The proxy is a Rust HTTP server bound to{" "}
        <Tok>127.0.0.1</Tok> and uses zero-copy streaming for response
        bodies, so SSE and large downloads pass through at native speed.
      </>
    ),
  },
  {
    q: "What does AI actually see when Phantom is installed?",
    a: (
      <>
        Your <Tok>.env</Tok> file contains <Tok>phm_xxxxxxxx</Tok> tokens
        instead of real values. Every AI tool (Claude Code, Cursor,
        Windsurf, Codex, anything else that reads .env) reads those tokens
        and only those tokens. The local proxy swaps them for real keys
        just before the outbound TLS connection — the AI never touches a
        real secret.
      </>
    ),
  },
  {
    q: "What if a phm_ token leaks from AI logs?",
    a: (
      <>
        Nothing happens. <Tok>phm_</Tok> tokens are session-scoped
        placeholders that have no value outside your local proxy. The real
        key never left your machine. Rotate the token with{" "}
        <Tok>phantom rotate</Tok> and the leaked one becomes inert.
      </>
    ),
  },
  {
    q: "How are real keys stored?",
    a: (
      <>
        OS keychain on macOS and Linux (Keychain Services / libsecret).
        Encrypted file fallback for CI and Docker, using ChaCha20-Poly1305
        with Argon2id key derivation. Vault retrieval returns{" "}
        <Tok>Zeroizing&lt;String&gt;</Tok> so plaintext is scrubbed from
        RAM by Drop. No plaintext ever touches disk outside the encrypted
        vault file.
      </>
    ),
  },
  {
    q: "Can the proxy be tricked into revealing the real key?",
    a: (
      <>
        Not through the AI tool. The real key only ever materialises in
        the outbound TLS connection to the upstream API — never in HTTP
        responses (those go back to the AI verbatim) and never in proxy
        logs (proxy logs the phm_ token, not the real value). Auth tokens
        on the proxy itself use constant-time comparison.
      </>
    ),
  },
  {
    q: "What about secrets in HTTP request bodies, not just headers?",
    a: (
      <>
        Yes — the proxy scans request headers, URL parameters, and JSON
        body fields for <Tok>phm_</Tok> tokens and replaces all of them.
        Streaming bodies (SSE, large uploads) are scanned chunk-by-chunk
        without buffering.
      </>
    ),
  },
  {
    q: "Can my team share secrets without sharing the .env?",
    a: (
      <>
        Yes — Pro tier ships shared cloud vaults with envelope encryption.
        Each team member has their own keypair; the vault is encrypted to
        every member&apos;s public key. We never see plaintext.
      </>
    ),
  },
  {
    q: "What if I want to leave Phantom?",
    a: (
      <>
        Your original <Tok>.env</Tok> is backed up automatically on init.
        Run <Tok>phantom unwrap</Tok> to restore it. Delete{" "}
        <Tok>.phantom.toml</Tok> and Phantom is gone — no lock-in, no
        migration scripts.
      </>
    ),
  },
];

export function FAQ() {
  return (
    <section id="faq" className="border-t border-border py-24 sm:py-28">
      <div className="mx-auto max-w-[860px] px-7">
        <div className="mb-12 text-center">
          <h2 className="text-[1.8rem] sm:text-[2.4rem] font-extrabold tracking-[-0.035em] leading-[1.08] text-white">
            Questions a security-minded developer would ask.
          </h2>
          <p className="mt-4 text-[0.98rem] text-t2 leading-[1.65]">
            If yours isn&apos;t here, file an issue on GitHub or email{" "}
            <a
              href="mailto:mason@ashlr.ai"
              className="text-blue-b hover:text-blue underline-offset-2 hover:underline"
            >
              mason@ashlr.ai
            </a>
            .
          </p>
        </div>

        <div className="rounded-2xl border border-border bg-s1 overflow-hidden">
          {QUESTIONS.map((item, i) => (
            <details
              key={item.q}
              className={
                "group [&>summary::-webkit-details-marker]:hidden " +
                (i === QUESTIONS.length - 1 ? "" : "border-b border-border")
              }
            >
              <summary className="flex items-center justify-between gap-4 cursor-pointer list-none px-6 py-5 hover:bg-s2/40 focus-visible:bg-s2/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-b focus-visible:ring-inset transition-colors">
                <span className="text-[0.95rem] font-semibold text-t1 leading-snug">
                  {item.q}
                </span>
                <span
                  aria-hidden
                  className="shrink-0 flex items-center justify-center h-7 w-7 rounded-full border border-border bg-s2/60 text-t3 group-open:rotate-45 group-open:text-blue-b transition-all duration-200"
                >
                  <svg
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    width="14"
                    height="14"
                  >
                    <path d="M12 5v14M5 12h14" />
                  </svg>
                </span>
              </summary>
              <div className="px-6 pb-6 text-[0.92rem] text-t2 leading-[1.7] max-w-[680px]">
                {item.a}
              </div>
            </details>
          ))}
        </div>
      </div>
    </section>
  );
}
