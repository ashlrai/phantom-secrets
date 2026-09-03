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
        aria-label={copied ? "Copied" : "Copy command"}
        className="copy-command copy-command--inline"
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
      className="copy-command"
    >
      <span>
        <span aria-hidden="true">$ </span>
        {text}
      </span>
      <span className="copy-command__icon" aria-hidden="true">
        {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
      </span>
    </button>
  );
}
