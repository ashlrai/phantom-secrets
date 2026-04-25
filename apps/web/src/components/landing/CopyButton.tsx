"use client";

import { useState } from "react";
import { posthog } from "@/lib/posthog";
import { Check, Copy } from "./Icons";

interface CopyButtonProps {
  text: string;
  variant?: "block" | "inline";
}

export function CopyButton({ text, variant = "block" }: CopyButtonProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      posthog.capture("command_copied", { command: text });
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      // Clipboard write can reject if the page lacks user-gesture context
      // or if the browser denies permission (Firefox over HTTP, etc.).
      // Stay silent — the button keeps its idle state so users see the failure.
    }
  };

  if (variant === "inline") {
    return (
      <button
        type="button"
        onClick={handleCopy}
        aria-label="Copy command"
        className="inline-flex items-center gap-1.5 text-t3 hover:text-blue-b transition-colors"
      >
        {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
      </button>
    );
  }

  return (
    <button
      type="button"
      onClick={handleCopy}
      aria-label="Copy command"
      className="group w-full flex items-center justify-between gap-3 bg-s2 border border-border hover:border-blue rounded-lg px-4 py-3 font-mono text-sm text-t1 text-left transition-colors cursor-pointer"
    >
      <span className="truncate">
        <span className="text-t3 select-none">$ </span>
        {text}
      </span>
      <span className="shrink-0 text-t3 group-hover:text-blue-b transition-colors">
        {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
      </span>
    </button>
  );
}
