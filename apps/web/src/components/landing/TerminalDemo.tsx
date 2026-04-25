"use client";

import { useEffect, useRef, useState } from "react";
import { useReducedMotion } from "motion/react";
import { Reveal } from "./Reveal";

interface CmdLine { kind: "cmd"; text: string }
interface OutLine { kind: "out"; html: string; delay?: number }
type Line = CmdLine | OutLine;

const SCRIPT: Line[] = [
  { kind: "cmd", text: "phantom sync --platform vercel" },
  {
    kind: "out",
    html: '<span class="text-blue-b">→</span> <span class="text-t2">Syncing 3 secret(s) to</span> <span class="text-blue-b">vercel</span><span class="text-t2">…</span>',
  },
  {
    kind: "out",
    html: '<span class="text-t2">   </span><span class="text-green font-semibold">+</span> <span class="text-t1">OPENAI_API_KEY</span> <span class="text-t2">(created)</span>',
    delay: 50,
  },
  {
    kind: "out",
    html: '<span class="text-t2">   </span><span class="text-green font-semibold">+</span> <span class="text-t1">STRIPE_SECRET</span> <span class="text-t2">(created)</span>',
    delay: 50,
  },
  {
    kind: "out",
    html: '<span class="text-t2">   </span><span class="text-green font-semibold">~</span> <span class="text-t1">DATABASE_URL</span> <span class="text-t2">(updated)</span>',
    delay: 50,
  },
  {
    kind: "out",
    html: '<span class="text-green font-semibold">ok</span> <span class="text-t2">vercel: 2 created, 1 updated</span>',
    delay: 300,
  },
  { kind: "cmd", text: "phantom cloud push" },
  {
    kind: "out",
    html: '<span class="text-blue-b">→</span> <span class="text-t2">Encrypting 3 secret(s) client-side…</span>',
  },
  {
    kind: "out",
    html: '<span class="text-green font-semibold">ok</span> <span class="text-t2">3 secret(s) synced to cloud (v1)</span><span class="cursor-blink"></span>',
  },
];

const PROMPT = '<span class="text-t3">$ </span>';
const CHAR_INTERVAL_MS = 28;
const POST_CMD_DELAY_MS = 200;
const DEFAULT_OUT_DELAY_MS = 60;

function renderCmd(text: string): string {
  return `${PROMPT}<span class="text-t1">${escapeHtml(text)}</span>`;
}

function renderLine(line: Line): string {
  return line.kind === "cmd" ? renderCmd(line.text) : line.html;
}

export function TerminalDemo() {
  const reduce = useReducedMotion();
  const containerRef = useRef<HTMLDivElement>(null);
  const [started, setStarted] = useState(false);
  const [lines, setLines] = useState<string[]>([]);

  // Trigger when terminal scrolls into view
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const obs = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) {
            setStarted(true);
            obs.disconnect();
          }
        });
      },
      { threshold: 0.2 },
    );
    obs.observe(el);
    return () => obs.disconnect();
  }, []);

  // Run the script
  useEffect(() => {
    if (!started) return;

    if (reduce) {
      setLines(SCRIPT.map(renderLine));
      return;
    }

    let cancelled = false;
    let i = 0;
    const out: string[] = [];
    setLines([]);

    const next = () => {
      if (cancelled || i >= SCRIPT.length) return;
      const ln = SCRIPT[i];
      if (ln.kind === "cmd") {
        let c = 0;
        const cmdIdx = out.length;
        out.push(PROMPT);
        setLines([...out]);
        const iv = window.setInterval(() => {
          if (cancelled) {
            window.clearInterval(iv);
            return;
          }
          if (c < ln.text.length) {
            out[cmdIdx] = renderCmd(ln.text.slice(0, c + 1));
            setLines([...out]);
            c++;
          } else {
            window.clearInterval(iv);
            i++;
            window.setTimeout(next, POST_CMD_DELAY_MS);
          }
        }, CHAR_INTERVAL_MS);
      } else {
        out.push(ln.html);
        setLines([...out]);
        i++;
        window.setTimeout(next, ln.delay ?? DEFAULT_OUT_DELAY_MS);
      }
    };

    next();
    return () => {
      cancelled = true;
    };
  }, [started, reduce]);

  return (
    <section className="border-t border-border py-24 sm:py-28 relative overflow-hidden">
      {/* Soft blue ambient glow behind the terminal */}
      <div
        aria-hidden
        className="pointer-events-none absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 h-[500px] w-[700px] rounded-full bg-blue/[0.05] blur-[140px]"
      />

      <div className="relative mx-auto max-w-[1080px] px-7">
        <Reveal>
          <div className="text-center mb-12">
            <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-border bg-s1 px-3.5 py-1 text-[0.72rem] font-mono font-medium tracking-[0.06em] text-t3 uppercase">
              // live demo
            </div>
            <h2 className="text-[1.7rem] sm:text-[2.2rem] font-extrabold tracking-[-0.04em] text-white mb-3">
              See it in action
            </h2>
            <p className="mx-auto max-w-[520px] text-t2 text-[0.95rem] sm:text-base leading-[1.7]">
              Protect secrets, sync to Vercel, back up to the cloud — all from
              one CLI.
            </p>
          </div>
        </Reveal>

        <Reveal delay={0.05}>
          <div
            ref={containerRef}
            className="mx-auto max-w-[760px] rounded-2xl border border-border bg-[#0d0d10] overflow-hidden shadow-[0_40px_100px_rgba(0,0,0,0.6),0_0_0_1px_rgba(255,255,255,0.04)_inset]"
          >
            {/* Window chrome */}
            <div className="flex items-center gap-0 border-b border-border bg-s1/80 backdrop-blur-sm">
              {/* Traffic lights */}
              <div className="flex items-center gap-1.5 px-4 py-3.5">
                <span className="h-[11px] w-[11px] rounded-full bg-[#ff5f57] ring-1 ring-black/20" />
                <span className="h-[11px] w-[11px] rounded-full bg-[#febc2e] ring-1 ring-black/20" />
                <span className="h-[11px] w-[11px] rounded-full bg-[#28c840] ring-1 ring-black/20" />
              </div>

              {/* Title bar */}
              <div className="flex flex-1 items-center justify-center gap-2 py-3">
                <span className="text-[0.72rem] text-t3 font-mono">
                  phantom — ~/my-app
                </span>
                {/* Live dot */}
                <span className="inline-flex items-center gap-1 rounded-full bg-green/10 px-2 py-0.5">
                  <span className="h-1.5 w-1.5 rounded-full bg-green animate-pulse" />
                  <span className="text-[0.6rem] font-mono text-green tracking-wider">LIVE</span>
                </span>
              </div>

              {/* Right spacer to balance the traffic lights */}
              <div className="w-[86px]" />
            </div>

            {/* Terminal body */}
            <div className="px-6 py-6 font-mono text-[0.82rem] leading-[2] min-h-[260px]">
              {lines.map((html, idx) => (
                <div
                  key={idx}
                  dangerouslySetInnerHTML={{ __html: `${html}<br>` }}
                />
              ))}
            </div>
          </div>
        </Reveal>
      </div>
    </section>
  );
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
