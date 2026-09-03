"use client";

import { useState } from "react";
import { posthog } from "@/lib/posthog";
import { Check, Copy } from "./Icons";

interface CopyButtonProps {
  text: string;
  variant?: "block" | "inline";
}

export function CopyButton({ text, variant = "block" }: CopyButtonProps) {
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      posthog.capture("command_copied", { variant });
      setCopyState("copied");
      window.setTimeout(() => setCopyState("idle"), 1800);
    } catch {
      // Clipboard write can reject if the page lacks user-gesture context
      // or if the browser denies permission (Firefox over HTTP, etc.).
      setCopyState("failed");
      window.setTimeout(() => setCopyState("idle"), 3000);
    }
  };

  const label =
    copyState === "copied"
      ? "Copied"
      : copyState === "failed"
        ? "Copy failed; select the command manually"
        : "Copy command";

  if (variant === "inline") {
    return (
      <button
        type="button"
        onClick={handleCopy}
        aria-label={label}
        className="copy-command copy-command--inline"
      >
        {copyState === "copied" ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
      </button>
    );
  }

  return (
    <button
      type="button"
      onClick={handleCopy}
      aria-label={label}
      className="copy-command"
    >
      <span>
        <span aria-hidden="true">$ </span>
        {text}
      </span>
      <span className="copy-command__icon" aria-hidden="true">
        {copyState === "copied" ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
      </span>
      <span className="sr-only" aria-live="polite">{copyState === "idle" ? "" : label}</span>
    </button>
  );
}
