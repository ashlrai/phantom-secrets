// Three-step "first 60 seconds" panel. Each step has the exact command,
// click-to-copy, and the literal expected output. Reduces install friction
// by removing every "wait what next?" moment.

import { CopyButton } from "./CopyButton";

const STEPS = [
  {
    n: "01",
    title: "Install",
    body: "One command. Downloads the binary for your platform.",
    cmd: "npx phantom-secrets init",
    out: `$ npx phantom-secrets init
->  Found 4 secrets in .env
ok  vault initialized · macOS Keychain
ok  .env rewritten with phm_ tokens
ok  pre-commit hook installed
ok  CLAUDE.md updated`,
  },
  {
    n: "02",
    title: "Wire it to your editor",
    body: "MCP registration so Claude / Cursor / Windsurf see Phantom as a tool.",
    cmd: "claude mcp add phantom-secrets-mcp -- npx phantom-secrets-mcp",
    out: `$ claude mcp add phantom-secrets-mcp \\
    -- npx phantom-secrets-mcp
ok  registered phantom-secrets-mcp
ok  24 tools available to Claude`,
  },
  {
    n: "03",
    title: "Code with AI normally",
    body: "Your AI tool reads phm_ tokens. The proxy injects real keys at the network layer.",
    cmd: "phantom exec -- claude",
    out: `$ phantom exec -- claude
->  proxy started on 127.0.0.1:8484
->  intercepting api.openai.com, api.anthropic.com,
    api.stripe.com (+10)
->  launching claude with PHANTOM_PROXY env`,
  },
];

export function QuickStart() {
  return (
    <section id="quickstart" className="border-t border-border py-24 sm:py-28">
      <div className="mx-auto max-w-[1100px] px-7">
        <div className="max-w-[640px] mb-12">
          <h2 className="text-[1.8rem] sm:text-[2.4rem] font-extrabold tracking-[-0.035em] leading-[1.08] text-white">
            Sixty seconds to a safe .env.
          </h2>
          <p className="mt-4 text-[0.98rem] text-t2 leading-[1.65]">
            Three commands. Real output. Nothing hidden. If anything looks
            different on your machine, run{" "}
            <code className="font-mono text-blue-b">phantom doctor</code>.
          </p>
        </div>

        <div className="space-y-3">
          {STEPS.map((s) => (
            <div
              key={s.n}
              className="grid grid-cols-1 lg:grid-cols-[1fr_1.15fr] gap-5 lg:gap-7 rounded-2xl border border-border bg-s1 p-6 sm:p-7"
            >
              <div>
                <div className="font-mono text-[0.78rem] text-blue-b mb-2">
                  Step {s.n}
                </div>
                <h3 className="text-[1.1rem] font-bold text-t1 mb-2">
                  {s.title}
                </h3>
                <p className="text-[0.9rem] text-t2 leading-[1.65] mb-4">
                  {s.body}
                </p>
                <CopyButton text={s.cmd} />
              </div>
              <pre className="rounded-lg border border-border bg-bg/70 p-4 font-mono text-[0.78rem] leading-[1.7] text-t1 overflow-x-auto whitespace-pre">
                {s.out}
              </pre>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
