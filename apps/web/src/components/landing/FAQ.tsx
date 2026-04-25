"use client";

import { useState } from "react";
import { Reveal } from "./Reveal";

const FAQS = [
  {
    q: "Does this slow down my AI requests?",
    a: "Roughly 0.5 ms of proxy overhead per request — nothing measurable in practice. The proxy runs on localhost, so there is no network hop; it is a socket-to-socket relay with a single scan over headers and body.",
  },
  {
    q: "What if the proxy crashes mid-request?",
    a: "The client gets a connection-refused error and retries as normal. The proxy is stateless — it holds no session or in-flight data — and restarts in under 100 ms. Your workflow resumes immediately.",
  },
  {
    q: "Can the proxy be tricked into revealing the real key?",
    a: "No. The real key only ever appears inside the outbound TLS connection to the upstream API. It is never written to logs, never returned in responses to the AI, and never persisted to disk after initial vault write. Phantom tokens in AI context are useless outside the proxy.",
  },
  {
    q: "What about secrets in HTTP request bodies, not just headers?",
    a: "Yes — the proxy scans the full request: headers, URL parameters, and the body. JSON, form-encoded, and raw text bodies are all scanned before forwarding.",
  },
  {
    q: "Is the encrypted vault actually encrypted, or is it security theater?",
    a: "ChaCha20-Poly1305 with an Argon2id key derivation function. Both are modern, widely audited, and post-quantum-considered. OS keychain is used when available (macOS Keychain, Linux Secret Service); the encrypted file fallback uses the same cipher suite for CI and Docker environments.",
  },
  {
    q: "What happens if I run phantom init on a repo that's already protected?",
    a: "It is idempotent. Existing phantom tokens are rotated and the vault is updated with fresh tokens. Real key values are preserved. Anything that isn't detected as a secret — NODE_ENV, PORT, DEBUG — is left untouched.",
  },
  {
    q: "Can my team share secrets without sharing the .env?",
    a: "Yes. The Pro tier provides shared cloud vaults with envelope encryption: each member's device holds its own key wrap, so no single plaintext is ever shared. Invite teammates with phantom team invite — they pull and unwrap on their own machine.",
  },
  {
    q: "What if I want to leave Phantom?",
    a: "Run phantom unwrap to restore your .env to its original plaintext form. A backup is maintained automatically by phantom init. There is no data format lock-in — secrets are standard key=value pairs once unwrapped.",
  },
];

function FAQItem({ q, a, index }: { q: string; a: string; index: number }) {
  const [open, setOpen] = useState(false);
  const id = `faq-${index}`;

  return (
    <Reveal delay={index * 0.03}>
      <div className="border-b border-border last:border-b-0">
        <button
          type="button"
          aria-expanded={open}
          aria-controls={id}
          onClick={() => setOpen((v) => !v)}
          className="w-full flex items-center justify-between gap-4 py-5 px-1 text-left group"
        >
          <span className="text-[0.92rem] sm:text-[0.96rem] font-medium text-t1 leading-snug group-hover:text-white transition-colors">
            {q}
          </span>
          {/* Plus/minus icon */}
          <span
            aria-hidden
            className={`shrink-0 w-5 h-5 relative text-t3 group-hover:text-blue-b transition-all duration-200 ${
              open ? "rotate-45" : "rotate-0"
            }`}
          >
            <svg
              viewBox="0 0 20 20"
              fill="none"
              stroke="currentColor"
              strokeWidth={1.8}
              strokeLinecap="round"
              className="w-full h-full transition-transform duration-200"
            >
              <path d="M10 4v12M4 10h12" />
            </svg>
          </span>
        </button>

        <div
          id={id}
          role="region"
          className={`overflow-hidden transition-all duration-300 ease-[cubic-bezier(0.16,1,0.3,1)] ${
            open ? "max-h-[320px] opacity-100 pb-5" : "max-h-0 opacity-0"
          }`}
        >
          <p className="px-1 text-t2 text-[0.88rem] leading-[1.7]">{a}</p>
        </div>
      </div>
    </Reveal>
  );
}

export function FAQ() {
  return (
    <section id="faq" className="border-t border-border py-24 sm:py-28">
      <div className="mx-auto max-w-[780px] px-7">
        <Reveal>
          <div className="text-center mb-14">
            <p className="text-[0.75rem] font-semibold tracking-[0.12em] uppercase text-blue mb-3">
              FAQ
            </p>
            <h2 className="text-[1.7rem] sm:text-[2.2rem] font-extrabold tracking-[-0.04em] text-white mb-3">
              Questions you&apos;d actually ask.
            </h2>
            <p className="mx-auto max-w-[460px] text-t2 text-[0.95rem] sm:text-base leading-[1.7]">
              The ones a security-minded developer asks before trusting a tool
              with their keys.
            </p>
          </div>
        </Reveal>

        <div className="rounded-2xl border border-border bg-s1 px-6 sm:px-8">
          {FAQS.map((item, i) => (
            <FAQItem key={item.q} q={item.q} a={item.a} index={i} />
          ))}
        </div>
      </div>
    </section>
  );
}
