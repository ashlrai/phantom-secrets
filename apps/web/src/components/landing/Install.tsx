"use client";

import { useState } from "react";
import { CopyButton } from "./CopyButton";
import { ClaudeLogo, CursorLogo, OpenAILogo, WindsurfLogo } from "./BrandLogos";

const TARGETS = [
  {
    id: "claude",
    label: "Claude Code",
    Logo: ClaudeLogo,
    cmd: "claude mcp add phantom-secrets-mcp -- npx phantom-secrets-mcp",
    note: "One command. Claude registers the MCP server and discovers all 24 tools.",
  },
  {
    id: "cursor",
    label: "Cursor",
    Logo: CursorLogo,
    cmd: '{"phantom":{"command":"npx","args":["phantom-secrets-mcp"]}}',
    note: "Settings → MCP Servers → paste the JSON. Cursor restarts the server automatically.",
  },
  {
    id: "windsurf",
    label: "Windsurf",
    Logo: WindsurfLogo,
    cmd: '{"phantom":{"command":"npx","args":["phantom-secrets-mcp"]}}',
    note: "Settings → MCP Configuration → paste. Same JSON, same protection.",
  },
  {
    id: "codex",
    label: "Codex / other",
    Logo: OpenAILogo,
    cmd: "npx phantom-secrets init",
    note: "Any tool that reads .env. Phantom protects the file; the tool never knows the difference.",
  },
];

export function Install() {
  const [active, setActive] = useState("claude");
  const current = TARGETS.find((t) => t.id === active) ?? TARGETS[0];

  return (
    <section id="install" className="border-t border-border py-24 sm:py-28">
      <div className="mx-auto max-w-[1100px] px-7">
        <div className="max-w-[640px] mb-12">
          <h2 className="text-[1.8rem] sm:text-[2.4rem] font-extrabold tracking-[-0.035em] leading-[1.08] text-white">
            Install in ten seconds.
          </h2>
          <p className="mt-4 text-[0.98rem] text-t2 leading-[1.65]">
            One CLI, one MCP registration. Pick your editor.
          </p>
        </div>

        <div className="rounded-2xl border border-border bg-s1 overflow-hidden">
          {/* Tabs */}
          <div className="flex border-b border-border overflow-x-auto">
            {TARGETS.map((t) => {
              const isActive = active === t.id;
              return (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => setActive(t.id)}
                  className={
                    "flex items-center gap-2 px-5 py-3.5 text-[0.85rem] font-medium border-b-2 transition-colors whitespace-nowrap " +
                    (isActive
                      ? "border-blue text-t1 bg-s2/60"
                      : "border-transparent text-t3 hover:text-t2")
                  }
                >
                  <t.Logo className="h-4 w-4" />
                  {t.label}
                </button>
              );
            })}
          </div>
          {/* Panel */}
          <div className="p-6 sm:p-7">
            <CopyButton text={current.cmd} />
            <p className="mt-4 text-[0.84rem] text-t3 leading-relaxed">
              {current.note}
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}
