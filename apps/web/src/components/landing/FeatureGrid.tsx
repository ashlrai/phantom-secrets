import { Reveal } from "./Reveal";
import {
  Cloud,
  Code,
  Lock,
  Plug,
  Shield,
  Sparkle,
  Terminal,
  Zap,
} from "./Icons";
import type { ReactNode } from "react";

interface Feature {
  icon: ReactNode;
  title: string;
  body: ReactNode;
  accent?: "blue" | "green" | "default";
  wide?: boolean;
}

const FEATURES: Feature[] = [
  {
    icon: <Lock className="w-5 h-5" />,
    title: "Encrypted vault",
    body: (
      <>
        ChaCha20-Poly1305 with Argon2id key derivation. OS keychain on
        macOS/Linux. Encrypted file fallback for CI and Docker — secrets at rest
        are always ciphertext.
      </>
    ),
    accent: "blue",
    wide: true,
  },
  {
    icon: <Plug className="w-5 h-5" />,
    title: "MCP-native",
    body: (
      <>
        Native Claude Code, Cursor, Windsurf, and Codex integration. AI manages
        secrets through MCP tools without ever seeing real values.
      </>
    ),
    accent: "blue",
    wide: true,
  },
  {
    icon: <Zap className="w-5 h-5" />,
    title: "Session tokens",
    body: (
      <>
        Fresh phantom tokens every session. If one leaks from AI logs or
        context, it&apos;s already invalid.
      </>
    ),
  },
  {
    icon: <Shield className="w-5 h-5" />,
    title: "Pre-commit hook",
    body: (
      <>
        <code className="text-blue-b font-mono text-[0.82rem]">phantom check</code>{" "}
        blocks commits containing unprotected secrets before they ship.
      </>
    ),
    accent: "green",
  },
  {
    icon: <Cloud className="w-5 h-5" />,
    title: "Platform sync",
    body: (
      <>
        Push secrets to Vercel and Railway. Pull to onboard new machines. No
        more copying keys through Slack.
      </>
    ),
  },
  {
    icon: <Sparkle className="w-5 h-5" />,
    title: "Smart detection",
    body: (
      <>
        Auto-detects 13+ services from key names. Knows{" "}
        <code className="text-blue-b font-mono text-[0.82rem]">OPENAI_API_KEY</code>{" "}
        from{" "}
        <code className="text-blue-b font-mono text-[0.82rem]">NODE_ENV</code>.
      </>
    ),
  },
  {
    icon: <Terminal className="w-5 h-5" />,
    title: "Streaming proxy",
    body: (
      <>
        Full SSE/streaming support. OpenAI and Anthropic streaming responses
        work perfectly through the proxy.
      </>
    ),
  },
  {
    icon: <Code className="w-5 h-5" />,
    title: "Open source",
    body: (
      <>MIT licensed. Written in Rust. 56 tests. Auditable, forkable, free forever.</>
    ),
    accent: "green",
  },
  {
    icon: <Cloud className="w-5 h-5" />,
    title: "Cloud sync",
    body: (
      <>
        <code className="text-blue-b font-mono text-[0.82rem]">phantom cloud push</code>{" "}
        backs up your vault to Phantom Cloud. Sync across machines. End-to-end
        encrypted.
      </>
    ),
  },
];

const ACCENT_CLASSES = {
  blue: {
    icon: "border-blue-d/40 bg-blue/10 text-blue-b",
    glow: "group-hover:opacity-100",
    glowColor: "bg-blue/[0.08]",
    border: "hover:border-blue-d",
  },
  green: {
    icon: "border-green/20 bg-green/10 text-green",
    glow: "group-hover:opacity-100",
    glowColor: "bg-green/[0.06]",
    border: "hover:border-green/40",
  },
  default: {
    icon: "border-border bg-s2 text-blue-b",
    glow: "group-hover:opacity-100",
    glowColor: "bg-blue/[0.05]",
    border: "hover:border-border-l",
  },
};

export function FeatureGrid() {
  return (
    <section id="features" className="border-t border-border py-24 sm:py-28">
      <div className="mx-auto max-w-[1080px] px-7">
        <Reveal>
          <div className="text-center mb-14">
            <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-border bg-s1 px-3.5 py-1 text-[0.72rem] font-mono font-medium tracking-[0.06em] text-t3 uppercase">
              // features
            </div>
            <h2 className="text-[1.7rem] sm:text-[2.2rem] font-extrabold tracking-[-0.04em] text-white mb-3">
              Security + developer experience
            </h2>
            <p className="mx-auto max-w-[520px] text-t2 text-[0.95rem] sm:text-base leading-[1.7]">
              Not just safer — faster. One tool for local dev, AI coding, and
              deployment.
            </p>
          </div>
        </Reveal>

        {/* Bento grid: first two cards span 2 cols on lg, rest fill 3-col */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-3">
          {FEATURES.map((f, i) => {
            const accent = ACCENT_CLASSES[f.accent ?? "default"];
            const colSpan = f.wide
              ? "lg:col-span-3"
              : "lg:col-span-2";

            return (
              <Reveal
                key={f.title}
                delay={(i % 3) * 0.04}
                className={`sm:col-span-1 ${colSpan}`}
              >
                <article className="group h-full rounded-2xl border border-border bg-s1 p-7 transition-all duration-200 hover:-translate-y-0.5 relative overflow-hidden">
                  {/* Hover glow */}
                  <div
                    className={`pointer-events-none absolute -top-10 -left-10 h-32 w-32 rounded-full ${accent.glowColor} blur-2xl opacity-0 transition-opacity duration-500 ${accent.glow}`}
                  />

                  <div className={`mb-4 inline-flex h-9 w-9 items-center justify-center rounded-lg border ${accent.icon}`}>
                    {f.icon}
                  </div>
                  <h3 className="text-[0.95rem] font-bold text-t1 mb-1.5">
                    {f.title}
                  </h3>
                  <p className="text-t2 text-[0.84rem] leading-[1.6]">{f.body}</p>
                </article>
              </Reveal>
            );
          })}
        </div>
      </div>
    </section>
  );
}
