"use client";

import { useEffect, useRef, useState } from "react";
import { capturePostHog } from "@/lib/posthog";
import { Check, Copy } from "./Icons";

interface CopyButtonProps {
  text: string;
  prompt?: string;
}

export function CopyButton({ text, prompt = "$" }: CopyButtonProps) {
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const resetTimer = useRef<number | null>(null);
  const attempt = useRef(0);

  useEffect(
    () => () => {
      attempt.current += 1;
      if (resetTimer.current !== null) window.clearTimeout(resetTimer.current);
    },
    [],
  );

  const resetAfter = (delay: number) => {
    if (resetTimer.current !== null) window.clearTimeout(resetTimer.current);
    resetTimer.current = window.setTimeout(() => {
      setCopyState("idle");
      resetTimer.current = null;
    }, delay);
  };

  const handleCopy = async () => {
    const currentAttempt = ++attempt.current;
    if (resetTimer.current !== null) {
      window.clearTimeout(resetTimer.current);
      resetTimer.current = null;
    }

    try {
      await navigator.clipboard.writeText(text);
      if (currentAttempt !== attempt.current) return;
      void capturePostHog("command_copied");
      setCopyState("copied");
      resetAfter(1800);
    } catch {
      // Clipboard write can reject if the page lacks user-gesture context
      // or if the browser denies permission (Firefox over HTTP, etc.).
      if (currentAttempt !== attempt.current) return;
      setCopyState("failed");
      resetAfter(3000);
    }
  };

  const label =
    copyState === "copied"
      ? "Copied"
      : copyState === "failed"
        ? "Copy failed; select the command manually"
        : "Copy command";

  return (
    <button
      type="button"
      onClick={handleCopy}
      title={label}
      className="copy-command"
    >
      <span>
        <span className="sr-only">Copy command: </span>
        <span aria-hidden="true">{prompt} </span>
        {text}
      </span>
      <span className="copy-command__icon" aria-hidden="true">
        {copyState === "copied" ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
      </span>
      <span className="sr-only" aria-live="polite">{copyState === "idle" ? "" : label}</span>
    </button>
  );
}
