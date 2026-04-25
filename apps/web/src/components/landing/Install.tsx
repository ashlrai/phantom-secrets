import { CopyButton } from "./CopyButton";
import { Reveal } from "./Reveal";

const TARGETS = [
  {
    label: "npm",
    cmd: "npx phantom-secrets init",
    sub: "Downloads binary automatically",
    featured: false,
  },
  {
    label: "Claude Code",
    cmd: "claude mcp add phantom-secrets-mcp -- npx phantom-secrets-mcp",
    sub: "One command, Claude handles the rest",
    featured: true,
  },
  {
    label: "Cursor",
    cmd: '{"phantom":{"command":"npx","args":["phantom-secrets-mcp"]}}',
    sub: "Add to Settings › MCP Servers",
    featured: false,
  },
  {
    label: "Windsurf / Codex",
    cmd: '{"phantom":{"command":"npx","args":["phantom-secrets-mcp"]}}',
    sub: "Any MCP-compatible AI coding tool",
    featured: false,
  },
];

export function Install() {
  return (
    <section className="border-t border-border py-24 sm:py-28">
      <div className="mx-auto max-w-[1080px] px-7">
        <Reveal>
          <div className="text-center mb-12">
            <h2 className="text-[1.7rem] sm:text-[2.2rem] font-extrabold tracking-[-0.04em] text-white">
              Install in 10 seconds
            </h2>
          </div>
        </Reveal>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {TARGETS.map((t, i) => (
            <Reveal key={t.label} delay={(i % 2) * 0.05}>
              <div
                className={[
                  "rounded-2xl border bg-s1 p-7 transition-colors h-full",
                  t.featured
                    ? "border-blue-d glow-blue-soft"
                    : "border-border hover:border-border-l",
                ].join(" ")}
              >
                <h3 className="text-[0.78rem] font-bold uppercase tracking-[0.06em] text-blue-b mb-3.5">
                  {t.label}
                </h3>
                <CopyButton text={t.cmd} />
                <p className="mt-3 text-[0.75rem] text-t3 text-center">{t.sub}</p>
              </div>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}
