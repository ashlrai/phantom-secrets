import { COMMERCIAL_CONTACT } from "@/lib/commercial-offerings";

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
        dotenv file. <Tok>phantom exec</Tok> gives the child fresh placeholders
        and a separate proxy bearer. On an exact supported route, the proxy
        injects only that route&apos;s vault value into its fixed auth header;
        client headers and bodies never resolve placeholders. Other files and
        unmanaged processes remain outside that boundary. Human plaintext reveal is a separate
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
        The proxy discards client control of the matched route&apos;s auth header
        and injects only that route&apos;s vault value there; client headers and
        bodies never resolve placeholders. It redacts recognized credential
        formats in responses. This reduces accidental exposure; it is not a
        substitute for provider scoping, rotation, or OS user-presence controls. Proxy session
        tokens use constant-time comparison.
      </>
    ),
  },
  {
    q: "What about secrets in HTTP request bodies, not just headers?",
    a: (
      <>
        Client headers and bodies never resolve <Tok>phm_</Tok> placeholders.
        Bodies are collected under explicit byte/time limits and forwarded
        byte-for-byte. Only an exact matched route can inject its own vault
        value into its fixed authentication header.
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
    <section id="faq" className="questions-section">
      <div className="landing-frame questions-section__layout">
        <div className="landing-section-heading questions-section__heading">
          <p className="landing-kicker">Review questions</p>
          <h2>Ask where the boundary ends.</h2>
          <p>
            Security claims are useful only when their assumptions and failure
            modes are visible. For a question not covered here, open a GitHub
            issue or email{" "}
            <a href={`mailto:${COMMERCIAL_CONTACT}`}>{COMMERCIAL_CONTACT}</a>.
          </p>
        </div>

        <div className="questions-list">
          {QUESTIONS.map((item) => (
            <details
              key={item.q}
            >
              <summary>
                <span>{item.q}</span>
                <span aria-hidden="true">+</span>
              </summary>
              <div>{item.a}</div>
            </details>
          ))}
        </div>
      </div>
    </section>
  );
}
