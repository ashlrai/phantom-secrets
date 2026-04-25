"use client";

import { useState } from "react";
import { CopyButton } from "./CopyButton";
import { Reveal } from "./Reveal";

const TARGETS = [
  {
    id: "npm",
    label: "CLI",
    sublabel: "npm / npx",
    cmd: "npx phantom-secrets init",
    sub: "Downloads binary automatically. Works everywhere Node is installed.",
    featured: false,
    icon: (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
        <path d="M0 0h16v16H0z" fill="#CB3837" />
        <path d="M3 3h10v10H8V6H6v7H3z" fill="white" />
      </svg>
    ),
  },
  {
    id: "claude",
    label: "Claude Code",
    sublabel: "MCP",
    cmd: "claude mcp add phantom-secrets-mcp -- npx phantom-secrets-mcp",
    sub: "One command. Claude handles discovery and tool registration automatically.",
    featured: true,
    icon: (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
        <rect width="16" height="16" rx="4" fill="#CC785C" />
        <path d="M8 3.5C5.515 3.5 3.5 5.515 3.5 8s2.015 4.5 4.5 4.5 4.5-2.015 4.5-4.5S10.485 3.5 8 3.5Z" fill="white" fillOpacity="0.9" />
        <path d="M6 8a2 2 0 1 1 4 0 2 2 0 0 1-4 0Z" fill="#CC785C" />
      </svg>
    ),
  },
  {
    id: "cursor",
    label: "Cursor",
    sublabel: "MCP JSON",
    cmd: '{"phantom":{"command":"npx","args":["phantom-secrets-mcp"]}}',
    sub: "Paste into Settings › MCP Servers. Cursor restarts the server automatically.",
    featured: false,
    icon: (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
        <rect width="16" height="16" rx="4" fill="#1A1A1A" />
        <path d="M4 4h8v8H4z" fill="none" stroke="white" strokeWidth="1.2" />
        <path d="M4 4l8 8" stroke="white" strokeWidth="1.2" />
      </svg>
    ),
  },
  {
    id: "windsurf",
    label: "Windsurf / Codex",
    sublabel: "MCP JSON",
    cmd: '{"phantom":{"command":"npx","args":["phantom-secrets-mcp"]}}',
    sub: "Any MCP-compatible AI coding tool. Same config, same protection.",
    featured: false,
    icon: (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
        <rect width="16" height="16" rx="4" fill="#0F172A" />
        <path d="M3 12 L8 4 L13 12" stroke="#38BDF8" strokeWidth="1.4" strokeLinejoin="round" fill="none" />
        <path d="M5.5 9h5" stroke="#38BDF8" strokeWidth="1.4" strokeLinecap="round" />
      </svg>
    ),
  },
];

export function Install() {
  const [active, setActive] = useState("claude");
  const current = TARGETS.find((t) => t.id === active) ?? TARGETS[0];

  return (
    <section className="border-t border-border py-24 sm:py-28">
      <div className="mx-auto max-w-[1080px] px-7">
        <Reveal>
          <div className="text-center mb-12">
            <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-border bg-s1 px-3.5 py-1 text-[0.72rem] font-mono font-medium tracking-[0.06em] text-t3 uppercase">
              // install
            </div>
            <h2 className="text-[1.7rem] sm:text-[2.2rem] font-extrabold tracking-[-0.04em] text-white mb-3">
              Install in 10 seconds
            </h2>
            <p className="mx-auto max-w-[480px] text-t2 text-[0.95rem] leading-[1.7]">
              Pick your tool. One command and you&apos;re protected.
            </p>
          </div>
        </Reveal>

        <Reveal delay={0.05}>
          <div className="mx-auto max-w-[680px]">
            {/* Tab bar */}
            <div className="flex items-center gap-1 rounded-xl border border-border bg-s1 p-1 mb-4">
              {TARGETS.map((t) => (
                <button
                  key={t.id}
                  onClick={() => setActive(t.id)}
                  className={[
                    "flex flex-1 items-center justify-center gap-2 rounded-lg px-3 py-2.5 text-[0.78rem] font-semibold transition-all duration-150 cursor-pointer",
                    active === t.id
                      ? "bg-s2 text-t1 shadow-[0_1px_3px_rgba(0,0,0,0.3)]"
                      : "text-t3 hover:text-t2",
                  ].join(" ")}
                >
                  <span className="flex-shrink-0">{t.icon}</span>
                  <span className="hidden sm:inline">{t.label}</span>
                  <span className="sm:hidden">{t.sublabel}</span>
                </button>
              ))}
            </div>

            {/* Panel */}
            <div
              className={[
                "rounded-2xl border p-7 transition-colors",
                current.featured
                  ? "border-blue-d bg-s1 shadow-[0_0_40px_rgba(var(--blue-rgb,59,130,246),0.06)]"
                  : "border-border bg-s1",
              ].join(" ")}
            >
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2.5">
                  <span className="flex-shrink-0">{current.icon}</span>
                  <span className="font-semibold text-t1 text-[0.9rem]">
                    {current.label}
                  </span>
                  <span className="rounded-md border border-border bg-s2 px-1.5 py-0.5 text-[0.68rem] font-mono text-t3">
                    {current.sublabel}
                  </span>
                </div>
                {current.featured && (
                  <span className="rounded-full border border-blue-d/40 bg-blue/10 px-2.5 py-0.5 text-[0.68rem] font-mono text-blue-b">
                    recommended
                  </span>
                )}
              </div>

              <CopyButton text={current.cmd} />

              <p className="mt-4 text-[0.8rem] text-t3 leading-[1.6]">
                {current.sub}
              </p>
            </div>
          </div>
        </Reveal>
      </div>
    </section>
  );
}
