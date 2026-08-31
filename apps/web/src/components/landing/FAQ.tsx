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
        Phantom adds a local Rust HTTP proxy bound to <Tok>127.0.0.1</Tok>.
        Request bodies are collected under byte and time limits; response
        streams remain bounded and incremental. Measure overhead in your own
        workload before adopting it on a latency-critical path.
      </>
    ),
  },
  {
    q: "What does AI actually see when Phantom is installed?",
    a: (
      <>
        Your <Tok>.env</Tok> file contains <Tok>phm_xxxxxxxx</Tok> tokens
        instead of real values. In the managed workflow, supported clients
        read those placeholders rather than provider values from the rewritten
        dotenv file. <Tok>phantom exec</Tok> gives the child fresh session
        tokens, and the authenticated local proxy resolves them only for
        configured upstream routes. Other files and unmanaged processes remain
        outside that boundary. Human plaintext reveal is a separate
        trusted-terminal action with no noninteractive bypass.
      </>
    ),
  },
  {
    q: "What if a phm_ token leaks from AI logs?",
    a: (
      <>
        A managed <Tok>.env</Tok> placeholder persists until you rotate it; it
        is not the provider credential and is not sufficient by itself to use
        the authenticated local proxy. <Tok>phantom exec</Tok> separately
        creates fresh session <Tok>phm_</Tok> values and a fresh{" "}
        <Tok>PHANTOM_PROXY_TOKEN</Tok> for the child process. Treat a leaked
        placeholder as sensitive metadata and run <Tok>phantom rotate</Tok>.
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
        RAM by Drop. Phantom&apos;s managed init path writes the vault before
        atomically replacing dotenv values and does not create a plaintext
        project-local backup. Existing backups, logs, and unmanaged tools are
        outside that boundary.
      </>
    ),
  },
  {
    q: "Can the proxy be tricked into revealing the real key?",
    a: (
      <>
        Supported proxy paths replace configured values and redact recognized
        credential formats in response headers and bodies before returning
        them. This reduces accidental exposure; it is not a substitute for
        provider scoping, rotation, or OS user-presence controls. Proxy session
        tokens use constant-time comparison.
      </>
    ),
  },
  {
    q: "What about secrets in HTTP request bodies, not just headers?",
    a: (
      <>
        The proxy scans supported request headers and body fields for
        <Tok>phm_</Tok> tokens. Bodies are collected under explicit byte/time
        limits before replacement. General upstream query-parameter
        substitution is not supported.
      </>
    ),
  },
  {
    q: "Can my team share secrets without sharing the .env?",
    a: (
      <>
        The repository includes Pro-gated team-vault source with envelope
        encryption for fixed-membership pilots. Each member has their own
        keypair; the vault is encrypted to every member&apos;s public key, and the
        service path accepts ciphertext. Hosted availability still requires a
        commissioned Phantom Cloud deployment. Member removal and automatic
        vault-key rotation are not shipped, so do not treat this as an
        offboarding control.
      </>
    ),
  },
  {
    q: "What if I want to leave Phantom?",
    a: (
      <>
        Phantom intentionally does not leave a plaintext <Tok>.env</Tok>
        backup during init. Keep an independent provider recovery path before
        migrating. <Tok>phantom unwrap</Tok> only reverses package-script
        wrapping; it does not restore dotenv values. To leave, recover or
        rotate credentials through the provider, update your dotenv file in a
        trusted terminal, then remove Phantom configuration.
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
          {QUESTIONS.map((item) => (
            <details
              key={item.q}
              className="group [&>summary::-webkit-details-marker]:hidden border-b border-border last:border-b-0"
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
