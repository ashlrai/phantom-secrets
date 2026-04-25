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
      // Just render everything immediately for reduced motion
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
        // Type the command character by character
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
    <section className="border-t border-border py-24 sm:py-28">
      <div className="mx-auto max-w-[1080px] px-7">
        <Reveal>
          <div className="text-center mb-12">
            <h2 className="text-[1.7rem] sm:text-[2.2rem] font-extrabold tracking-[-0.04em] text-white mb-3">
              See it in action
            </h2>
            <p className="mx-auto max-w-[520px] text-t2 text-[0.95rem] sm:text-base leading-[1.7]">
              The full workflow from protecting secrets to deploying them.
            </p>
          </div>
        </Reveal>

        <Reveal delay={0.05}>
          <div
            ref={containerRef}
            className="mx-auto max-w-[760px] rounded-2xl border border-border bg-s1 overflow-hidden shadow-[0_32px_80px_rgba(0,0,0,0.5),0_0_0_1px_rgba(255,255,255,0.03)_inset]"
          >
            <div className="flex items-center gap-1.5 px-4 py-3.5 border-b border-border">
              <span className="tl-dot bg-red" />
              <span className="tl-dot bg-[#eab308]" />
              <span className="tl-dot bg-green" />
              <span className="ml-auto text-[0.72rem] text-t3 font-mono">
                ~/my-app
              </span>
            </div>
            <div className="px-5 py-5 font-mono text-[0.82rem] leading-[2] min-h-[260px]">
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
