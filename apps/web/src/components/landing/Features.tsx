// Three features. One row each. Code samples to make it real.
// Each feature carries a small row of brand logos above the title to
// anchor it back to the actual services the feature touches.

import type { ComponentType, SVGProps } from "react";
import {
  ClaudeLogo,
  CursorLogo,
  GitHubLogo,
  OpenAILogo,
  RailwayLogo,
  VercelLogo,
  WindsurfLogo,
} from "./BrandLogos";

type LogoComponent = ComponentType<SVGProps<SVGSVGElement>>;

interface Feature {
  title: string;
  body: React.ReactNode;
  code: string;
  logos: LogoComponent[];
}

const FEATURES: Feature[] = [
  {
    title: "MCP-native, every editor",
    body: (
      <>
        Claude Code, Cursor, Windsurf, Codex. Phantom registers as an MCP server
        so AI can manage secrets through a tool interface — without ever seeing
        the values.
      </>
    ),
    code: `$ claude mcp add phantom-secrets-mcp \\
    -- npx phantom-secrets-mcp
ok  registered 17 tools`,
    logos: [ClaudeLogo, CursorLogo, WindsurfLogo, OpenAILogo],
  },
  {
    title: "Catches leaks before they ship",
    body: (
      <>
        <code className="font-mono text-blue-b">phantom check</code> runs as a
        pre-commit hook and blocks any commit containing an unprotected secret.
        Nothing slips past.
      </>
    ),
    code: `$ git commit -m "wip"
!  3 unprotected secrets in src/config.ts:
   line 4:  OPENAI_API_KEY=sk-proj-...
   line 7:  STRIPE_KEY=sk_live_...
fix: run \`phantom add\` to vault them.`,
    logos: [GitHubLogo],
  },
  {
    title: "One source of truth, everywhere",
    body: (
      <>
        Push secrets to Vercel and Railway. Pull on a new machine. Sync to
        Phantom Cloud (end-to-end encrypted) so your team is never stuck Slacking
        a <code className="font-mono text-blue-b">.env</code>.
      </>
    ),
    code: `$ phantom sync --platform vercel
ok  vercel: 4 created, 1 updated
$ phantom pull --from vercel
ok  imported 5 secrets to vault`,
    logos: [VercelLogo, RailwayLogo],
  },
];

export function Features() {
  return (
    <section id="features" className="border-t border-border py-24 sm:py-28">
      <div className="mx-auto max-w-[1100px] px-7">
        <div className="max-w-[640px] mb-12">
          <h2 className="text-[1.8rem] sm:text-[2.4rem] font-extrabold tracking-[-0.035em] leading-[1.08] text-white">
            Built like a real CLI.
          </h2>
          <p className="mt-4 text-[0.98rem] text-t2 leading-[1.65]">
            No dashboard required. Everything lives in your terminal, your
            editor, and your existing infrastructure.
          </p>
        </div>

        <div className="space-y-4">
          {FEATURES.map((f) => (
            <article
              key={f.title}
              className="grid grid-cols-1 lg:grid-cols-[1fr_1.05fr] gap-6 lg:gap-10 items-start rounded-2xl border border-border bg-s1 p-7 sm:p-8"
            >
              <div>
                {/* Brand-logo chips — tie the feature to the actual services */}
                <div className="flex items-center gap-2 mb-4">
                  {f.logos.map((Logo, i) => (
                    <span
                      key={i}
                      className="inline-flex h-7 w-7 items-center justify-center rounded-md border border-border bg-s2/80"
                    >
                      <Logo className="h-3.5 w-3.5" />
                    </span>
                  ))}
                </div>
                <h3 className="text-[1.15rem] font-bold text-t1 mb-3">
                  {f.title}
                </h3>
                <p className="text-[0.92rem] text-t2 leading-[1.7]">{f.body}</p>
              </div>
              <pre className="rounded-lg border border-border bg-bg/60 px-4 py-3.5 font-mono text-[0.78rem] leading-[1.6] text-t1 overflow-x-auto whitespace-pre">
                {f.code}
              </pre>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
